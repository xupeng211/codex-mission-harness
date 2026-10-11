"""Restricted, observable Codex exec invocation for Harness self-review.

The configured model is sent to a pinned official binary using the canonical
ChatGPT reviewer auth home. Only transport proxy/CA variables are inherited.
No result is accepted without a completed turn and a final structured message.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .model_registry import ModelSpec
from .resource_gate import model_request

CANONICAL_BINARY = Path("/usr/lib/chatgpt/resources/codex")
CANONICAL_HOME = Path("/home/xupeng/.cmh-openai-reviewer-home")
PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
               "http_proxy", "https_proxy", "all_proxy", "no_proxy")
CA_NAMES = ("CODEX_CA_CERTIFICATE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
            "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE")
MAX_PROMPT_BYTES = 400_000
MAX_RESPONSE_BYTES = 128_000
# Codex JSONL may contain several agent-message events before the bounded
# final structured response. Keep a separate finite transport envelope.
MAX_EVENT_STREAM_BYTES = 2_000_000


class InvocationFailure(RuntimeError):
    def __init__(self, category: str, reason: str, evidence: dict):
        super().__init__(reason)
        self.category = category
        self.reason = reason
        self.evidence = evidence


@dataclass(frozen=True)
class InvocationResult:
    response: str
    evidence: dict


def _regular_private(path: Path, mode: int) -> None:
    info = path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode):
        raise ValueError("canonical Codex authentication metadata is unsafe")


def canonical_environment(source: dict[str, str] | None = None,
                          *, binary: Path = CANONICAL_BINARY,
                          codex_home: Path = CANONICAL_HOME) -> dict[str, str]:
    """Copy only transport settings from the caller, without provider routing."""
    source = os.environ if source is None else source
    binary_info = binary.stat()
    home_info = codex_home.lstat()
    if (not binary.is_absolute() or binary.is_symlink() or
            not stat.S_ISREG(binary_info.st_mode) or binary_info.st_uid != 0 or
            stat.S_IMODE(binary_info.st_mode) & 0o022 or
            not codex_home.is_absolute() or codex_home.is_symlink() or
            not stat.S_ISDIR(home_info.st_mode) or home_info.st_uid != os.getuid() or
            stat.S_IMODE(home_info.st_mode) != 0o700):
        raise ValueError("canonical Codex executable or home is unsafe")
    _regular_private(codex_home / "auth.json", 0o600)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
           "CODEX_HOME": str(codex_home)}
    env.update({name: source[name] for name in PROXY_NAMES if name in source})
    for name in CA_NAMES:
        if name not in source:
            continue
        paths = source[name].split(os.pathsep) if name == "SSL_CERT_DIR" else [source[name]]
        if all(_trusted_ca_path(Path(value), directory=name == "SSL_CERT_DIR") for value in paths):
            env[name] = source[name]
    return env


def _trusted_ca_path(path: Path, *, directory: bool) -> bool:
    """Only inherit system-owned, non-writable CA roots."""
    try:
        info = path.lstat()
        return (path.is_absolute() and not path.is_symlink() and info.st_uid == 0
                and not stat.S_IMODE(info.st_mode) & 0o022
                and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and all(stat.S_ISDIR(parent.lstat().st_mode)
                        and parent.lstat().st_uid == 0
                        and not stat.S_IMODE(parent.lstat().st_mode) & 0o022
                        for parent in path.parents))
    except OSError:
        return False


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate Codex JSON field")
        value[key] = item
    return value


def parse_events(raw: bytes) -> dict:
    """Read bounded JSONL and require a real completed Codex turn."""
    if len(raw) > MAX_EVENT_STREAM_BYTES:
        raise ValueError("Codex event stream exceeds bound")
    types = []
    messages = 0
    events = []
    for line in raw.splitlines():
        try:
            event = json.loads(line, object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            raise ValueError("Codex event stream is not JSONL") from None
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ValueError("invalid Codex event")
        kind = event["type"]
        events.append(event)
        types.append(kind)
        if kind == "item.completed" and isinstance(event.get("item"), dict) and \
                event["item"].get("type") == "agent_message":
            messages += 1
    if (types.count("thread.started") != 1 or types.count("turn.started") != 1 or
            types.count("turn.completed") != 1 or "turn.failed" in types or
            "error" in types or messages < 1 or types[-1] != "turn.completed"):
        raise ValueError("Codex turn lacked a valid terminal completion")
    thread = events[0].get("thread_id") if types[0] == "thread.started" else None
    agent = next((e["item"] for e in reversed(events) if e["type"] == "item.completed"
                  and isinstance(e.get("item"), dict) and e["item"].get("type") == "agent_message"), {})
    usage = None
    try:
        if not isinstance(thread, str) or not thread or not isinstance(agent.get("id"), str):
            raise ValueError("Codex usage lacks thread/message identity")
        if types.index("turn.started") <= types.index("thread.started"):
            raise ValueError("Codex turn order invalid")
        usage = normalize_openai_usage(events[-1].get("usage"))
    except ValueError:
        pass  # Successful output without verifiable usage still settles UNKNOWN.
    return {"event_types": types, "agent_messages": messages,
            "terminal_completion": True, "thread_id": thread,
            "turn_ordinal": 1, "agent_message_id": agent.get("id"), "agent_message_text": agent.get("text"), "usage": usage}


def normalize_openai_usage(raw):
    """Codex exec terminal usage: cached input is part of total input;
    reasoning is part of output. Missing categories are never inferred as zero.
    """
    fields = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens")
    if (not isinstance(raw, dict) or any(type(raw.get(k)) is not int or raw[k] < 0 for k in fields)
            or raw["cached_input_tokens"] > raw["input_tokens"]
            or raw["reasoning_output_tokens"] > raw["output_tokens"]):
        raise ValueError("Codex terminal usage is missing or invalid")
    return {"usage_scope": "CODEX_EXEC_TURN", "raw_usage_fields": raw,
            "tokens": {"input": raw["input_tokens"] - raw["cached_input_tokens"],
                       "cache": raw["cached_input_tokens"], "output": raw["output_tokens"],
                       "reasoning": raw["reasoning_output_tokens"]},
            "cost_classification": "OBSERVED_UNBILLED"}


def _persist_transport(prompt, stdout, stderr, response, spec, command_sha):
    """Persist before ephemeral cleanup, under the active signed reservation."""
    from .resource_gate import _active_reservation, canonical, digest, _write_atomic
    from . import formal_delivery_gate as gate
    active = _active_reservation.get()
    if active is None or active.ledger_key_path is None:
        return None  # Transport-only fixtures/legacy execution cannot certify formal usage.
    auth = gate.load_authorization()
    key = gate._read(active.ledger_key_path)
    row = next((r for r in gate._verify_child(active.ledger, key, auth)["requests"]
                if r["request_id"] == active.request_id), {})
    if (row.get("status") != "STARTED" or row.get("prompt_sha256") != digest(prompt)
            or (row.get("provider"), row.get("model")) != (spec.provider, spec.model)
            or spec.identity() != auth["runtime"]["models"]["openai"]):
        raise ValueError("Codex capture differs from active request/runtime/model")
    parent = active.ledger.parent / "openai-invocations"
    parent.mkdir(mode=0o700, exist_ok=True)
    if (parent.is_symlink() or parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise ValueError("Codex evidence directory must be private")
    directory = parent / active.request_id
    directory.mkdir(mode=0o700)  # Never overwrite an earlier physical attempt.
    paths = {}
    for name, raw in (("stdout.jsonl", stdout), ("stderr", stderr), ("response.json", response)):
        path = directory / name
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        paths[name] = {"path": str(path), "sha256": digest(raw)}
    binding = {"request_id": active.request_id, "authorization_sha256": active.authorization_sha256,
               "runtime_sha256": digest(canonical(auth["runtime"])), "model": spec.identity(),
               "prompt_sha256": digest(prompt), "command_sha256": command_sha, "files": paths}
    from .resource_gate import sign_authorization
    path = directory / "binding.json"
    _write_atomic(path, sign_authorization(binding, key))
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return {"path": str(path), "sha256": digest(path.read_bytes())}


def verify_openai_usage(usage, record, auth, key):
    """Re-read signed raw evidence at settlement; caller claims cannot substitute it."""
    from . import formal_delivery_gate as gate
    from .resource_gate import canonical, digest
    ref = usage["transport_binding"]
    binding = gate._signed(ref["path"], ref["sha256"], key)
    if (binding["request_id"] != record["request_id"]
            or binding["authorization_sha256"] != record["authorization_sha256"]
            or binding["runtime_sha256"] != digest(canonical(auth["runtime"]))
            or binding["model"] != auth["runtime"]["models"]["openai"]
            or binding["model"]["model"] != record["model"]
            or binding["prompt_sha256"] != record["prompt_sha256"]):
        raise ValueError("Codex raw evidence request/runtime/model mismatch")
    if set(binding["files"]) != {"stdout.jsonl", "stderr", "response.json"}:
        raise ValueError("Codex raw evidence files incomplete")
    raw = {}
    for name, file in binding["files"].items():
        raw[name] = gate._read(file["path"])
        if digest(raw[name]) != file["sha256"]:
            raise ValueError("Codex raw evidence hash mismatch")
    events = parse_events(raw["stdout.jsonl"])
    if (not isinstance(events["agent_message_text"], str) or
            json.loads(events["agent_message_text"], object_pairs_hook=_unique_pairs) !=
            json.loads(raw["response.json"], object_pairs_hook=_unique_pairs)):
        raise ValueError("Codex terminal message differs from persisted response")
    expected = events["usage"]
    if expected is None:
        raise ValueError("Codex raw evidence contains no verified usage")
    expected = dict(expected, transport_binding=ref,
                    thread_id=events["thread_id"], turn_ordinal=events["turn_ordinal"],
                    agent_message_id=events["agent_message_id"], response_sha256=digest(raw["response.json"]))
    if usage != expected:
        raise ValueError("Codex normalized usage or turn/response identity mismatch")
    return True


def _matches_schema(value: object, schema: dict) -> bool:
    """Validate the bounded JSON Schema subset emitted by Harness."""
    allowed = {"type", "properties", "required", "additionalProperties", "items",
               "enum", "minLength", "maxLength", "minimum", "pattern"}
    if not isinstance(schema, dict) or set(schema) - allowed:
        return False
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            return False
        properties = schema.get("properties", {})
        if not isinstance(properties, dict) or not set(schema.get("required", [])).issubset(value):
            return False
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        return all(key not in properties or _matches_schema(item, properties[key])
                   for key, item in value.items())
    if kind == "array":
        return isinstance(value, list) and all(_matches_schema(item, schema.get("items", {}))
                                               for item in value)
    if kind == "string":
        if not isinstance(value, str):
            return False
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1_000_000):
            return False
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            return False
    elif kind == "integer":
        if type(value) is not int or value < schema.get("minimum", -1_000_000_000):
            return False
    elif kind is not None:
        return False
    return "enum" not in schema or value in schema["enum"]


def _failure_category(stderr: bytes, stdout: bytes, *, timed_out: bool) -> str:
    if timed_out:
        return "TURN_TIMEOUT_UNDIAGNOSED"
    content = (stderr + b"\n" + stdout).decode("utf-8", "replace").casefold()
    if re.search(r"\b(?:401|403)\b", content):
        return "AUTHENTICATION_FAILURE"
    if re.search(r"unauthori|authentication|invalid.token|login required", content):
        return "AUTHENTICATION_FAILURE"
    if re.search(r"model.*(unsupported|not found|unavailable)|unsupported.*model", content):
        return "MODEL_UNAVAILABLE_OR_UNSUPPORTED"
    if re.search(r"hit.*usage limit|usage[ _]limit.*(?:reached|exceeded)|quota.*(?:exhausted|exceeded)|(?:subscription|membership).*(?:unavailable|expired|inactive)|account capacity blocked|insufficient_quota", content):
        return "SUBSCRIPTION_UNAVAILABLE"
    if re.search(r"rate.limit|capacity|overload|server.busy", content):
        return "TRANSIENT_CAPACITY"
    if re.search(r"connection|network|timeout|stream|proxy|disconnect", content):
        return "TRANSIENT_TRANSPORT"
    return "CLI_OR_CONFIG_FAILURE"


def _event_error_bytes(raw: bytes) -> bytes:
    """Classify native error events without scanning reviewed agent-message text."""
    errors = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(event, dict) and event.get('type') in {'error', 'turn.failed'}:
            error = event.get('error')
            if isinstance(error, dict):
                errors.extend(str(error.get(key, '')) for key in ('code', 'message'))
            elif isinstance(error, str):
                errors.append(error)
            for key in ('code', 'message'):
                if isinstance(event.get(key), str):
                    errors.append(event[key])
    return '\n'.join(errors).encode('utf-8')


def _failure_markers(stderr: bytes, stdout: bytes) -> dict:
    """Keep only fixed diagnostic labels, never provider text or credentials."""
    content = (stderr + b"\n" + stdout).decode("utf-8", "replace").casefold()
    return {"http_401": bool(re.search(r"\b401\b", content)),
            "http_403": bool(re.search(r"\b403\b", content)),
            "http_429": bool(re.search(r"\b429\b", content)),
            "auth_refresh_mentioned": "refresh" in content,
            "connection_error_mentioned": any(marker in content for marker in
                                              ("connection reset", "disconnect", "proxy error"))}


def _observed_events(raw: bytes) -> dict:
    """Summarize an incomplete stream without treating it as completion."""
    types = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            break
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            break
        types.append(event["type"])
    return {"observed_event_types": types[:1000], "observed_event_count": len(types),
            "turn_started_observed": "turn.started" in types,
            "terminal_observed": any(item in types for item in
                                     ("turn.completed", "turn.failed"))}


def _invoke_openai_unmetered(prompt: str, spec: ModelSpec, schema: dict, *, timeout: int = 120,
                  binary: Path = CANONICAL_BINARY,
                  codex_home: Path = CANONICAL_HOME,
                  source_env: dict[str, str] | None = None,
                  transport_sink=None) -> InvocationResult:
    from .formal_delivery_gate import require_active_transport
    require_active_transport(spec.provider, spec.model, prompt=prompt.encode(), claim_send=True)
    from .formal_delivery_gate import bounded_delivery_timeout
    timeout = bounded_delivery_timeout(timeout)
    from .formal_delivery_gate import NEW_MISSION, is_delivery_mission, require_provider_credential, _read
    if is_delivery_mission(os.environ.get("CMH_RESOURCE_MISSION_ID")):
        require_provider_credential("openai", _read(Path(codex_home) / "auth.json"))
    if spec.provider != "openai" or not spec.model or not spec.reasoning_effort:
        raise ValueError("configured OpenAI model and reasoning are required")
    if timeout < 1 or timeout > 900:
        raise ValueError("Codex timeout must be bounded")
    if not isinstance(prompt, str) or len(prompt.encode()) > MAX_PROMPT_BYTES:
        raise ValueError("Codex prompt exceeds bound")
    env = canonical_environment(source_env, binary=binary, codex_home=codex_home)
    with tempfile.TemporaryDirectory(prefix="cmh-openai-review-") as temporary:
        root = Path(temporary)
        schema_path = root / "schema.json"
        output = root / "result.json"
        schema_path.write_text(json.dumps(schema, sort_keys=True), encoding="utf-8")
        command = [str(binary), "exec", "--json", "--ephemeral", "--ignore-user-config",
                   "--ignore-rules", "--skip-git-repo-check", "--sandbox", "read-only",
                   "--model", spec.model, "-c",
                   f'model_reasoning_effort="{spec.reasoning_effort}"',
                   "--output-schema", str(schema_path), "--output-last-message",
                   str(output), "-"]
        command_sha = hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=root, env=env,
                                   start_new_session=True)
        started = time.monotonic()
        try:
            stdout, stderr = process.communicate(prompt.encode(), timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            timed_out = True
        except KeyboardInterrupt:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        except OSError as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE", "Codex process I/O failed",
                                    {"provider": spec.provider, "model": spec.model,
                                     "reasoning_effort": spec.reasoning_effort,
                                     "command_sha256": command_sha,
                                     "io_error_class": type(exc).__name__}) from exc
        response_bytes = output.read_bytes() if output.is_file() and output.stat().st_size <= MAX_RESPONSE_BYTES else b""
        persisted = _persist_transport(prompt.encode(), stdout, stderr, response_bytes, spec, command_sha)
        if transport_sink is not None:
            transport_sink(prompt.encode(), stdout, stderr)
        evidence = {"binary": str(binary), "codex_home": str(codex_home),
                    "provider": spec.provider, "model": spec.model,
                    "reasoning_effort": spec.reasoning_effort,
                    "command_sha256": command_sha,
                    "environment_keys": sorted(env),
                    "exit_code": process.returncode, "timed_out": timed_out,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                    "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "failure_markers": _failure_markers(stderr, stdout),
                    **_observed_events(stdout)}
        if timed_out or process.returncode != 0:
            raise InvocationFailure(_failure_category(stderr, _event_error_bytes(stdout), timed_out=timed_out),
                                    "canonical Codex invocation did not complete", evidence)
        try:
            events = parse_events(stdout)
        except ValueError as exc:
            category = _failure_category(stderr, _event_error_bytes(stdout), timed_out=False)
            raise InvocationFailure(category, str(exc), evidence) from exc
        evidence.update({k: v for k, v in events.items() if k != "agent_message_text"})
        if not output.is_file() or output.stat().st_size > MAX_RESPONSE_BYTES:
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE",
                                    "Codex final structured response is missing or oversized", evidence)
        try:
            response = output.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE",
                                    "Codex final structured response could not be read",
                                    dict(evidence, io_error_class=type(exc).__name__)) from exc
        try:
            value = json.loads(response)
        except ValueError as exc:
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE",
                                    "Codex final response is not JSON", evidence) from exc
        if not _matches_schema(value, schema):
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE",
                                    "Codex final response does not match requested schema", evidence)
        evidence["response_sha256"] = hashlib.sha256(response.encode()).hexdigest()
        evidence["transport_binding"] = persisted
        if events["usage"] is not None and persisted is not None:
            evidence["usage"] = dict(events["usage"], transport_binding=persisted,
                thread_id=events["thread_id"], turn_ordinal=events["turn_ordinal"],
                agent_message_id=events["agent_message_id"], response_sha256=hashlib.sha256(response_bytes).hexdigest())
        else:
            evidence["usage"] = None
        evidence["structured_result_present"] = True
        return InvocationResult(response, evidence)


def invoke_openai(prompt: str, spec: ModelSpec, schema: dict, *, timeout: int = 120,
                  binary: Path = CANONICAL_BINARY, codex_home: Path = CANONICAL_HOME,
                  source_env: dict[str, str] | None = None,
                  transport_sink=None) -> InvocationResult:
    """Reserve the original Mission's resources before any Codex subprocess."""
    if spec.provider != "openai" or not isinstance(prompt, str):
        raise ValueError("configured OpenAI model and prompt are required")
    from .formal_delivery_gate import require_invocation_spec
    require_invocation_spec(spec)
    with model_request(provider="openai", model=spec.model, prompt=prompt.encode(),
                       stage=os.environ.get("CMH_RESOURCE_STAGE", "openai-invocation")) as reservation:
        try:
            result = _invoke_openai_unmetered(prompt, spec, schema, timeout=timeout,
                                             binary=binary, codex_home=codex_home,
                                             source_env=source_env, transport_sink=transport_sink)
        except InvocationFailure as exc:
            if exc.category != 'SUBSCRIPTION_UNAVAILABLE':
                raise
            from .resource_gate import SubscriptionPause
            raise SubscriptionPause('Provider subscription capacity exhausted; refresh availability evidence',
                                    provider_attempted=True) from None
        reservation.observe(result.evidence.get("usage"))
        return result

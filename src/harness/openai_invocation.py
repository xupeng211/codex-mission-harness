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
from dataclasses import dataclass
from pathlib import Path

from .model_registry import ModelSpec

CANONICAL_BINARY = Path("/usr/lib/chatgpt/resources/codex")
CANONICAL_HOME = Path("/home/xupeng/.footballprediction/canonical-codex-reviewer")
PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
               "http_proxy", "https_proxy", "all_proxy", "no_proxy")
CA_NAMES = ("CODEX_CA_CERTIFICATE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
            "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE")
MAX_PROMPT_BYTES = 400_000
MAX_RESPONSE_BYTES = 128_000


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
        if all(Path(value).is_absolute() and Path(value).exists() and
               not Path(value).is_symlink() for value in paths):
            env[name] = source[name]
    return env


def parse_events(raw: bytes) -> dict:
    """Read bounded JSONL and require a real completed Codex turn."""
    if len(raw) > MAX_RESPONSE_BYTES * 4:
        raise ValueError("Codex event stream exceeds bound")
    types = []
    messages = 0
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            raise ValueError("Codex event stream is not JSONL") from None
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ValueError("invalid Codex event")
        kind = event["type"]
        types.append(kind)
        if kind == "item.completed" and isinstance(event.get("item"), dict) and \
                event["item"].get("type") == "agent_message":
            messages += 1
    if (types.count("thread.started") != 1 or types.count("turn.started") != 1 or
            types.count("turn.completed") != 1 or "turn.failed" in types or
            "error" in types or messages < 1 or types[-1] != "turn.completed"):
        raise ValueError("Codex turn lacked a valid terminal completion")
    return {"event_types": types, "agent_messages": messages,
            "terminal_completion": True}


def _failure_category(stderr: bytes, stdout: bytes, *, timed_out: bool) -> str:
    if timed_out:
        return "TRANSIENT_TRANSPORT"
    content = (stderr + b"\n" + stdout).decode("utf-8", "replace").casefold()
    if re.search(r"unauthori|authentication|invalid.token|login required", content):
        return "AUTHENTICATION_FAILURE"
    if re.search(r"model.*(unsupported|not found|unavailable)|unsupported.*model", content):
        return "MODEL_UNAVAILABLE_OR_UNSUPPORTED"
    if re.search(r"rate.limit|capacity|overload|server.busy", content):
        return "TRANSIENT_CAPACITY"
    if re.search(r"connection|network|timeout|stream|proxy|disconnect", content):
        return "TRANSIENT_TRANSPORT"
    return "CLI_OR_CONFIG_FAILURE"


def invoke_openai(prompt: str, spec: ModelSpec, schema: dict, *, timeout: int = 120,
                  binary: Path = CANONICAL_BINARY,
                  codex_home: Path = CANONICAL_HOME,
                  source_env: dict[str, str] | None = None) -> InvocationResult:
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
        try:
            stdout, stderr = process.communicate(prompt.encode(), timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            timed_out = True
        evidence = {"binary": str(binary), "codex_home": str(codex_home),
                    "provider": spec.provider, "model": spec.model,
                    "reasoning_effort": spec.reasoning_effort,
                    "command_sha256": command_sha,
                    "environment_keys": sorted(env),
                    "exit_code": process.returncode, "timed_out": timed_out,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
        if timed_out or process.returncode != 0:
            raise InvocationFailure(_failure_category(stderr, stdout, timed_out=timed_out),
                                    "canonical Codex invocation did not complete", evidence)
        try:
            events = parse_events(stdout)
        except ValueError as exc:
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE", str(exc), evidence) from exc
        evidence.update(events)
        if not output.is_file() or output.stat().st_size > MAX_RESPONSE_BYTES:
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE",
                                    "Codex final structured response is missing or oversized", evidence)
        response = output.read_text(encoding="utf-8")
        try:
            value = json.loads(response)
        except ValueError as exc:
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE",
                                    "Codex final response is not JSON", evidence) from exc
        if not isinstance(value, dict):
            raise InvocationFailure("CLI_OR_CONFIG_FAILURE",
                                    "Codex final response has invalid structure", evidence)
        evidence["response_sha256"] = hashlib.sha256(response.encode()).hexdigest()
        evidence["structured_result_present"] = True
        return InvocationResult(response, evidence)

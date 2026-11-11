"""One-shot Antigravity second review, using the existing supervised lifecycle.

Raw CLI evidence is private. This is a Harness adapter, not a project-native
DeepSeek/Claude receipt and not an attestation of the deployed model weights.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

BACKEND = "antigravity-cli"
PROVIDER = "antigravity"
PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def write(path, value):
    with Path(path).open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value if isinstance(value, bytes) else value.encode())


def identity(profile):
    binary = Path(profile["cli_path"])
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Antigravity requires an existing absolute CLI executable")
    # Version is a non-inference query; never probe authentication or models.
    version = subprocess.check_output([str(binary), "--version"], timeout=10, text=True).strip()
    return {"configured": profile, "backend": BACKEND, "requested_model": profile["model"],
            "effort": profile["effort"], "deployment_identity": "UNKNOWN",
            "runtime_version": version, "executable_sha256": sha(binary.read_bytes()),
            "adapter_sha256": sha(Path(__file__).read_bytes())}


def environment():
    # Cached desktop login only. Do not inherit API keys, alternate endpoints,
    # workspace injection, NODE_OPTIONS, or tool-specific settings overrides.
    from .sandbox import SAFE_PATH
    allowed = ("HOME", "USER", "LOGNAME", "DISPLAY", "WAYLAND_DISPLAY",
               "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_CONFIG_HOME",
               "XDG_DATA_HOME", "XDG_CACHE_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {k: os.environ[k] for k in (*allowed, *PROXY_KEYS) if k in os.environ}
    env.update(PATH=SAFE_PATH, LANG="C.UTF-8")
    return env


def proxy_facts(env):
    facts = {}
    for key in PROXY_KEYS:
        value = env.get(key)
        if key.lower() == "no_proxy":
            # Preserve only non-secret bypass host patterns, never URL userinfo.
            facts[key] = {"set": value is not None, "bypass": [
                x if re.fullmatch(r"[A-Za-z0-9.*:/_\[\]-]+", x) and "://" not in x else "REDACTED"
                for x in (value or "").replace(" ", "").split(",") if x]}
        else:
            try:
                parsed = urlsplit(value or "")
                host = parsed.hostname
                facts[key] = {"set": value is not None, "scheme": parsed.scheme,
                              "host": "loopback" if host in {"localhost", "127.0.0.1", "::1"} else "REDACTED" if host else None,
                              "port": parsed.port}
            except ValueError:
                facts[key] = {"set": value is not None, "parse": "UNKNOWN"}
    return {"child_environment": facts, "selected_node": "UNKNOWN", "actual_route": "UNKNOWN",
            "gui_proxy_equivalence": "UNKNOWN"}


def snapshot(root):
    result = {}
    for path in sorted(Path(root).rglob("*")):
        if path.is_symlink():
            raise ValueError("Antigravity input contains a symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
        elif not path.is_dir():
            raise ValueError("Antigravity input contains a non-regular entry")
    return result


def binding(result):
    return {"stage": "antigravity-review", "mission": result["mission_id"],
            "target": result["target"], "backend": BACKEND, "lane": "second_reviewer",
            "profile_identity": result["runtime_identity"], "argv": result["executed_runner_argv"],
            "cwd": result["workspace"], "operation": result["stdout_path"],
            "lifecycle": str(Path(result["stdout_path"]).with_suffix(".review")),
            "input_sha256": sha(canonical(result["input_before"]).encode()),
            "control_inputs": result["control_inputs"]}


def validate_stop(result, target):
    from .appserver_process import validate_supervised_stop
    if result["target"] != target or result["backend"] != BACKEND:
        raise ValueError("Antigravity review target/backend changed")
    path = Path(result["stdout_path"])
    if (path.resolve(strict=True) != path or
            result["review_lifecycle"]["path"] != str(path.with_suffix(".review.stop.json"))):
        raise ValueError("Antigravity lifecycle belongs to another operation")
    code = validate_supervised_stop(result["review_lifecycle"], binding(result))
    if code != result["exit_code"]:
        raise ValueError("Antigravity process exit evidence differs")


def report(envelope, target, workspace, review_root):
    # Never extract a PASS-looking suffix from an ERROR, concatenated document,
    # stream fragment or malformed response. JSON fences alone are harmless.
    if (not isinstance(envelope, dict) or envelope.get("status") != "SUCCESS"
            or envelope.get("error") or envelope.get("finished_reason") not in (None, "", "stop", "completed")):
        raise ValueError("Antigravity did not establish a successful CLI terminal state")
    raw = envelope.get("response")
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith("```json\n") and text.endswith("\n```"):
            text = text[8:-4]
        value = document(text)
    else:
        value = raw
    if (not isinstance(value, dict) or value.get("completion") != "COMPLETE"
            or value.get("verdict") not in {"PASS", "FAIL"}
            or value.get("target") != {"base": target["base"], "head": target["head"],
                                        "binding_sha256": sha(canonical(target).encode())}
            or not isinstance(value.get("read_scope"), list) or not value["read_scope"]
            or any(not isinstance(x, str) or not x.strip() for x in value["read_scope"])
            or not isinstance(value.get("context_gaps"), list)
            or any(not isinstance(x, str) for x in value["context_gaps"])):
        raise ValueError("Antigravity report incomplete or version/range binding invalid")
    output = json.loads(canonical(value["review"]))
    for finding in output.get("findings", []):
        location = finding["code_location"]
        relative = Path(location["absolute_file_path"]).relative_to(Path(workspace) / "source")
        if ".." in relative.parts:
            raise ValueError("Antigravity finding escapes independent source input")
        location["absolute_file_path"] = str(Path(review_root) / relative)
    from .factory import review_verdict
    verdict, findings = review_verdict(output, Path(review_root), target)
    if verdict != value["verdict"]:
        raise ValueError("Antigravity declared verdict contradicts findings")
    return value, output, verdict, findings


def validate(result, target, review_root):
    validate_stop(result, target)
    if result["exit_code"] != 0 or snapshot(result["workspace"]) != result["input_before"]:
        raise ValueError("Antigravity process failed or independent input changed")
    raw = Path(result["stdout_path"]).read_bytes()
    if sha(raw) != result["stdout_sha256"]:
        raise ValueError("Antigravity original stdout changed")
    for item in result["control_inputs"]:
        if sha(Path(item["path"]).read_bytes()) != item["sha256"]:
            raise ValueError("Antigravity prompt/settings changed")
    return report(document(raw), target, result["workspace"], review_root)


def operational_fields(path):
    """Only fixed operational captures; never copy arbitrary log lines/bodies."""
    retry, associations = [], []
    with path.open(errors="replace") as stream:
        for line in stream:
            stamp = re.match(r"[IWEF]\d{4} (\d{2}:\d{2}:\d{2}\.\d+)", line)
            log_time = stamp[1] if stamp else "UNKNOWN"
            match = re.search(r"Run: attempt (\d+) failed \((INTERNAL|UNAVAILABLE|DEADLINE_EXCEEDED)(?: \(code (\d+)\))?", line)
            if match:
                retry.append({"attempt": int(match[1]), "code_name": match[2],
                              "wrapped_code": int(match[3]) if match[3] else None,
                              "http_status": "UNKNOWN", "log_local_time": log_time})
            match = re.search(r"ResponseID[=: ]+([A-Za-z0-9_-]{8,128})", line)
            if match:
                trace = re.search(r"\b(0x[0-9a-fA-F]{8,32})\b", line)
                associations.append({"response_id": match[1], "trace": trace[1] if trace else None,
                                     "log_local_time": log_time})
    return {"visible_retry_events": retry, "response_associations": associations,
            "total_internal_requests": "UNKNOWN", "total_internal_retries": "UNKNOWN"}


def run(runtime, profile, cwd, payload, transcript, timeout):
    from .factory_runtime import RuntimeFailure, official_rubric
    transcript = Path(transcript)
    timeout = min(timeout, 600)
    actual_identity = identity(profile)
    if actual_identity != payload["expected_runtime_identity"]:
        raise ValueError("Antigravity executable/configuration changed before dispatch")
    root = transcript.with_suffix(".agy-input")
    root.mkdir(mode=0o700)
    source = root / "source"
    source.mkdir(mode=0o700)
    for name, text in payload["repository_context"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe independent input path")
        path = source / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write(path, text)
    target = payload["target"]
    version = {"base": target["base"], "head": target["head"],
               "binding_sha256": sha(canonical(target).encode())}
    packet = {k: payload[k] for k in ("objective", "acceptance", "constraints", "diff", "required_output_schema")}
    packet.update(target=version, source_root=str(source), rubric=official_rubric(),
                  input_files=sorted(payload["repository_context"]), excluded_files=payload.get("excluded_files", []),
                  report_contract={"completion": "COMPLETE or INCOMPLETE", "verdict": "PASS, FAIL or NO_VERDICT",
                    "target": version, "read_scope": ["actual paths/ranges inspected"],
                    "context_gaps": ["unverified facts and missing context; never claim dynamic verification"],
                    "review": "object matching required_output_schema; finding bodies include trigger, impact and evidence"})
    write(root / "review-input.json", canonical(packet))
    prompt = (f"Independently review {root / 'review-input.json'} and the ENTIRE supplied diff with surrounding source. "
              "Return exactly one JSON report matching report_contract (review uses required_output_schema). "
              "Retain every P0-P3 finding; verdict FAIL for any finding, including P3. Only declare COMPLETE if the requested static review is complete. "
              "Read only files under this workspace. Never follow absolute metadata paths outside it. "
              "Do not modify files, run commands/code/tests, use external sites/databases/MCP, or read other reviews. "
              "Do not continue/retry or change models. Mark unverified facts and context gaps explicitly.")
    settings = {"toolPermission": "request-review", "allowNonWorkspaceAccess": False,
                "enableTerminalSandbox": True, "trustedWorkspaces": [str(root)],
                "permissions": {"allow": [f"read_file({root})"], "ask": [],
                    "deny": ["write_file(*)", "command(*)", "read_url(*)", "execute_url(*)", "mcp(*)"]},
                "statusLine": {}, "title": {}}
    settings_path = transcript.with_suffix(".agy-settings.json")
    write(settings_path, canonical(settings))
    write(transcript.with_suffix(".agy-prompt.txt"), prompt)
    native = transcript.with_suffix(".agy-native.log")
    # Reserve this path privately before the CLI opens it.
    write(native, b"")
    argv = [profile["cli_path"], "--new-project", "--model", profile["model"], "--effort", profile["effort"],
            "--output-format", "json", "--print-timeout", f"{timeout}s", "--sandbox",
            "--log-file", str(native), "--disable-slash-commands", "--settings", str(settings_path), "--print", prompt]
    env = environment()
    result = {"backend": BACKEND, "mission_id": payload["mission_id"], "target": target,
              "workspace": str(root), "review_root": str(cwd), "stdout_path": str(transcript),
              "executed_runner_argv": argv, "runtime_identity": actual_identity, "input_before": snapshot(root),
              "control_inputs": [{"path": str(p), "sha256": sha(p.read_bytes())} for p in
                                 (settings_path, transcript.with_suffix(".agy-prompt.txt"))]}
    write(transcript.with_suffix(".agy-launch.json"), canonical({**result, "proxy": proxy_facts(env),
        "prompt_sha256": sha(prompt.encode()), "settings_sha256": sha(settings_path.read_bytes()),
        "model_window_seconds": timeout, "stop_budget_seconds": 60, "logical_launches": 1,
        "physical_cost": "UNKNOWN", "entitlement_consumption": "UNKNOWN", "strong_read_only_isolation": "UNPROVEN"}))
    life = transcript.with_suffix(".review")
    classification = {"exit_class": "UNKNOWN", "internal_request_count": "UNKNOWN", "deployment_identity": "UNKNOWN"}
    envelope = None
    try:
        code, proof = runtime._supervised_review_step(binding(result), argv, root, env, life, timeout)
        result.update(exit_code=code, review_lifecycle=proof)
        write(transcript, life.read_bytes())
        result["stdout_sha256"] = sha(transcript.read_bytes())
        envelope = document(transcript.read_text())
        if not isinstance(envelope, dict):
            raise ValueError("CLI output is not a JSON object")
        classification.update({k: envelope.get(k) for k in
            ("status", "error", "finished_reason", "duration_seconds", "conversation_id", "usage", "num_turns")})
        classification["failure_layer"] = "UNKNOWN"
        if envelope.get("status") == "ERROR":
            classification["exit_class"] = "CLI_REPORTED_ERROR"
        if envelope.get("finished_reason") in {"timeout", "print_timeout"}:
            classification["exit_class"] = "CLI_TIMEOUT"
        # Tool completion and report acceptance remain separate facts.
        if (code == 0 and envelope.get("status") == "SUCCESS" and not envelope.get("error")
                and envelope.get("finished_reason") in (None, "", "stop", "completed")):
            classification["exit_class"] = "NORMAL"
        value, output, verdict, findings = validate(result, target, cwd)
        classification["report_accepted"] = True
        result.update(output=output, report=value, review_status=verdict, findings=findings,
                      usage=envelope.get("usage"), diagnostics=classification)
        return result
    except Exception as exc:
        # Never copy arbitrary CLI errors into a public exception. Originals
        # remain in this operation's private directory, even for exit=0 ERROR.
        stop_path = life.with_suffix(life.suffix + ".stop.json")
        classification["acceptance_error_type"] = type(exc).__name__
        classification["tool_completed"] = bool(isinstance(envelope, dict) and envelope.get("status") == "SUCCESS"
                                                 and not envelope.get("error") and result.get("exit_code") == 0)
        classification["report_accepted"] = False
        if stop_path.is_file():
            stop = json.loads(stop_path.read_text())
            classification["controller_outcome"] = stop["outcome"]
            classification["exit_code"] = stop["exit_code"]
            classification["termination_signal"] = -stop["exit_code"] if stop["exit_code"] < 0 else None
            classification["local_stop"] = stop["stop"]["proof"]
            if stop["outcome"] in {"timeout", "cancelled"}:
                classification["exit_class"] = "CONTROLLER_TIMEOUT" if stop["outcome"] == "timeout" else "CANCELLED"
        failure = RuntimeFailure("Antigravity execution/report not accepted; see private operation evidence",
                                 envelope.get("usage") if isinstance(envelope, dict) else None,
                                 result["runtime_identity"])
        raise failure from exc
    finally:
        # No model reasoning is inspected. Native logs remain raw/private;
        # public JSON fields are the only automatic diagnostic extraction.
        try:
            after = snapshot(root)
        except ValueError:
            after = None
        write(transcript.with_suffix(".agy-input-after.json"), canonical(after))
        classification.update(operational_fields(native))
        if classification["exit_class"] == "NORMAL":
            classification.update(tool_completed=True, local_stop="ECHILD",
                                  exit_code=result["exit_code"], termination_signal=None)
        write(transcript.with_suffix(".agy-diagnostics.json"), canonical(classification))


def artifact(review):
    return review["review_artifact"] if review.get("backend") == BACKEND else review["canonical_receipt"]


def receipts(reviews):
    from .factory_project import LANES
    return {(PROVIDER if r.get("backend") == BACKEND else LANES[r["lane"]]): artifact(r) for r in reviews}

"""Bounded, secret-free diagnostics for standalone reviewer CLI failures."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


STREAM_LIMIT = 128_000
TRANSIENT = frozenset({"RATE_LIMIT", "TRANSPORT_ERROR", "PROVIDER_ERROR"})

_PATTERNS = {
    "CLI_USAGE_ERROR": r"(?:^|\n)usage:|unknown option|unrecognized option|unknown flag",
    "INVALID_ARGUMENT": r"invalid argument|invalid value|missing required argument|expected argument",
    "AUTH_ERROR": r"\b(?:401|403)\b|unauthori[sz]ed|authentication failed|invalid[ -]token|login required",
    "RATE_LIMIT": r"\b429\b|rate[ -]?limit|too many requests",
    "QUOTA_ERROR": r"quota exceeded|insufficient balance|billing limit|credit exhausted",
    "TRANSPORT_ERROR": r"connection refused|connection reset|network error|proxy error|disconnect|socket error|dns error",
    "PROVIDER_ERROR": r"\b5(?:00|02|03|04)\b|internal server error|service unavailable|temporarily unavailable|provider overloaded",
    "CONTEXT_LIMIT": r"context length|context window|prompt too long|input too large|too many tokens|maximum context",
    "SCHEMA_INVOCATION_ERROR": r"invalid json schema|unsupported schema|schema validation.*request|structured output.*unsupported",
    "LOCAL_LAUNCHER_ERROR": r"cannot find module|module not found|executable not found|permission denied|settings file.*invalid",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def command_identity(command: list[str]) -> str:
    """Include settings content, while normalizing its random temporary name."""
    normalized = list(command)
    if "--settings" in normalized:
        index = normalized.index("--settings") + 1
        settings = Path(normalized[index])
        normalized[index] = {"settings_sha256": digest(settings.read_bytes())}
    return digest(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode())


def environment_identity(env: dict[str, str]) -> str:
    """Do not hash or include auth, proxy URLs, cookies, or arbitrary inherited values."""
    safe = {key: env.get(key) for key in ("HOME", "PATH", "LANG", "ANTHROPIC_BASE_URL",
                                         "CLAUDE_CODE_SIMPLE")}
    safe["transport_variable_names"] = sorted(key for key in env if key not in safe
                                                and not any(marker in key.upper() for marker in
                                                            ("TOKEN", "KEY", "AUTH", "COOKIE", "PASSWORD", "SECRET")))
    safe["credential_variables_present"] = sorted(key for key in env if key in
                                                    {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"})
    return digest(json.dumps(safe, sort_keys=True, separators=(",", ":")).encode())


def _marker_source(stdout: bytes, stderr: bytes) -> str:
    """Only inspect CLI error fields; successful structured model text is untrusted source."""
    parts = [stderr[:STREAM_LIMIT].decode("utf-8", "replace")]
    try:
        wrapper = json.loads(stdout[:STREAM_LIMIT])
    except (ValueError, UnicodeError):
        return "\n".join(parts)
    if isinstance(wrapper, dict) and wrapper.get("is_error") is True:
        for key in ("result", "error", "terminal_reason"):
            if isinstance(wrapper.get(key), str):
                parts.append(wrapper[key][:STREAM_LIMIT])
        status = wrapper.get("api_error_status")
        if isinstance(status, int):
            parts.append(str(status))
    return "\n".join(parts)


def classify_nonzero(stdout: bytes, stderr: bytes, exit_code: int) -> tuple[str, dict[str, bool], bool, str]:
    if exit_code < 0:
        return "SIGNALLED", {}, False, "process terminated by signal"
    source = _marker_source(stdout, stderr).casefold()
    markers = {category: bool(re.search(pattern, source, re.IGNORECASE | re.MULTILINE))
               for category, pattern in _PATTERNS.items()}
    found = [name for name, matched in markers.items() if matched]
    if len(found) != 1:
        return "UNKNOWN_NONZERO_EXIT", markers, False, (
            "conflicting sanitized markers" if found else "no recognized sanitized marker")
    category = found[0]
    allowed = category in TRANSIENT
    return category, markers, allowed, ("explicit transient marker" if allowed else "nontransient marker")


def stream_metadata(stdout: bytes | None, stderr: bytes | None) -> dict:
    result = {}
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        value = raw or b""
        result.update({f"{name}_present": bool(value), f"{name}_size": len(value),
                       f"{name}_sha256": digest(value),
                       f"{name}_truncated": len(value) >= STREAM_LIMIT})
    return result


def cli_wrapper_summary(stdout: bytes | None) -> dict:
    """Retain only typed CLI envelope fields, never model text or error prose."""
    try:
        wrapper = json.loads((stdout or b"")[:STREAM_LIMIT])
    except (ValueError, UnicodeError):
        return {"is_error": None, "api_error_status": None, "subtype": None}
    if not isinstance(wrapper, dict):
        return {"is_error": None, "api_error_status": None, "subtype": None}
    status = wrapper.get("api_error_status")
    subtype = wrapper.get("subtype")
    return {"is_error": wrapper.get("is_error") if type(wrapper.get("is_error")) is bool else None,
            "api_error_status": status if type(status) is int and 100 <= status <= 599 else None,
            "subtype": subtype if isinstance(subtype, str) and subtype in
            {"success", "error_during_execution"} else None}

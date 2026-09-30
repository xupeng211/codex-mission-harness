#!/usr/bin/env python3
"""Durable, exact-diff DeepSeek review for this repository only.

The caller supplies a token-file path at execution time; no credential is ever
stored in the mission, journal, receipt, or repository.  Receipt publication is
commit-last: an incomplete run has no receipt and is never an approval.
"""
from __future__ import annotations

import argparse, base64, hashlib, hmac, json, os, pwd, re, shutil, signal, stat, subprocess, sys, tempfile, time, uuid
from pathlib import Path
from urllib.parse import urlsplit

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from harness.review_failures import (  # noqa: E402
    ReviewFailureClassification,
    ReviewFailureDetails,
    classify_process_failure,
)

VERSION = "cmh-deepseek-review/v5"
MODEL = "deepseek-flash"
ENDPOINT = "https://api.deepseek.com/anthropic"
CHUNK_BYTES = 32000
AGGREGATE_GROUP_BYTES = 96000
MAX_REVIEW_PROMPT_BYTES = 400000
GROUP_OUTPUT_FORMAT_RETRY_LIMIT = 1
_GIT_ENV = {
    "PATH": os.defpath,
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_COUNT": "0",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
}
_PROXY_ENV_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)
_CA_ENV_NAMES = (
    "CODEX_CA_CERTIFICATE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
    "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE",
)

_REVIEW_PROPERTIES = {
    "review_result": {"enum": ["PASS", "FAIL"]},
    "findings": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["severity", "title", "evidence"],
        "properties": {
            "severity": {"enum": ["P0", "P1", "P2", "P3"]},
            "title": {"type": "string"},
            "evidence": {"type": "string"},
        },
    }},
}
_DISPOSITION_SCHEMA = {
    "type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["chunk_index", "finding_index", "source_severity",
                     "finding_sha256", "decision", "rationale"],
        "properties": {
            "chunk_index": {"type": "integer", "minimum": 0},
            "finding_index": {"type": "integer", "minimum": 0},
            "source_severity": {"enum": ["P0", "P1", "P2"]},
            "finding_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "decision": {"enum": ["UPHELD", "DISPUTED"]},
            "rationale": {"type": "string", "minLength": 24},
        },
    },
}
_FINAL_DISPOSITION_SCHEMA = {
    "type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["group_index", "finding_index", "source_severity",
                     "finding_sha256", "decision", "rationale"],
        "properties": {
            "group_index": {"type": "integer", "minimum": 0},
            "finding_index": {"type": "integer", "minimum": 0},
            "source_severity": {"enum": ["P0", "P1", "P2"]},
            "finding_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "decision": {"enum": ["UPHELD"]},
            "rationale": {"type": "string", "minLength": 24},
        },
    },
}
CHUNK_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["review_result", "findings"],
    "properties": _REVIEW_PROPERTIES,
}
AGGREGATE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["review_result", "findings", "dispositions"],
    "properties": {**_REVIEW_PROPERTIES, "dispositions": _FINAL_DISPOSITION_SCHEMA},
}
GROUP_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["review_result", "findings", "dispositions", "summary"],
    "properties": {
        **_REVIEW_PROPERTIES,
        "dispositions": _DISPOSITION_SCHEMA,
        "summary": {"type": "string", "minLength": 32, "maxLength": 4000},
    },
}

def canon(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def digest(value): return hashlib.sha256(value).hexdigest()

def open_private_directory(path, repo_root, *, create=True, secure=True):
    """Open an external owner-controlled directory without following links.

    Evidence directories are tightened to 0700. Credential parent directories
    are only checked for unsafe writes so reading an existing token never
    changes its surrounding filesystem metadata.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None or not hasattr(os, "open"):
        raise ValueError("safe no-follow evidence access is unavailable")
    supplied = Path(path)
    if ".." in supplied.parts:
        raise ValueError("evidence path cannot contain parent traversal")
    target = Path(os.path.abspath(supplied))
    repository = Path(repo_root).resolve(strict=True)
    if target == repository or repository in target.parents:
        raise ValueError("evidence directory must be outside the reviewed repository")

    uid = os.getuid() if hasattr(os, "getuid") else None
    home = Path(pwd.getpwuid(uid).pw_dir) if uid is not None else Path.home()
    try:
        target.relative_to(home)
        anchor, anchor_kind = home, "home"
    except ValueError:
        anchor, anchor_kind = Path("/"), "root"
        for parent in target.parents:
            try:
                info = parent.lstat()
            except OSError:
                continue
            if stat.S_IMODE(info.st_mode) & stat.S_ISVTX:
                anchor, anchor_kind = parent, "sticky"
                break

    flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    current_path = Path("/")
    current_fd = os.open("/", flags)
    private_started = False
    try:
        # ``Path.parts`` omits the root component when slicing with [1:], so
        # a root anchor would otherwise never be observed inside the loop.
        # Validate and activate it before walking its children.
        if anchor == Path("/"):
            root_info = os.fstat(current_fd)
            root_mode = stat.S_IMODE(root_info.st_mode)
            if anchor_kind == "home":
                if (uid is not None and root_info.st_uid != uid) or root_mode & 0o022:
                    raise ValueError("owner home is not a stable evidence anchor")
            elif anchor_kind == "sticky":
                if ((uid is not None and root_info.st_uid not in {0, uid})
                        or not root_mode & stat.S_ISVTX):
                    raise ValueError("shared evidence anchor is not sticky and trusted")
            elif root_info.st_uid != 0 or root_mode & 0o022:
                raise ValueError("evidence path has an untrusted root ancestor")
            private_started = True
        for component in target.parts[1:]:
            child_path = current_path / component
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create or not private_started:
                    raise ValueError("evidence directory ancestor is unavailable")
                os.mkdir(component, 0o700, dir_fd=current_fd)
                child_fd = os.open(component, flags, dir_fd=current_fd)
            info = os.fstat(child_fd)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child_fd)
                raise ValueError("evidence path contains a non-directory")
            mode = stat.S_IMODE(info.st_mode)
            at_anchor = child_path == anchor
            if at_anchor:
                if anchor_kind == "home":
                    if uid is not None and info.st_uid != uid or mode & 0o022:
                        os.close(child_fd)
                        raise ValueError("owner home is not a stable evidence anchor")
                elif anchor_kind == "sticky":
                    if (uid is not None and info.st_uid not in {0, uid}) or not mode & stat.S_ISVTX:
                        os.close(child_fd)
                        raise ValueError("shared evidence anchor is not sticky and trusted")
                elif info.st_uid != 0 or mode & 0o022:
                    os.close(child_fd)
                    raise ValueError("evidence path has an untrusted root ancestor")
                private_started = True
            elif private_started:
                if uid is not None and info.st_uid != uid:
                    os.close(child_fd)
                    raise ValueError("private evidence directory is not owner-owned")
                if secure:
                    os.fchmod(child_fd, 0o700)
                    if stat.S_IMODE(os.fstat(child_fd).st_mode) != 0o700:
                        os.close(child_fd)
                        raise ValueError("private evidence directory could not be secured")
                elif mode & 0o022:
                    os.close(child_fd)
                    raise ValueError("credential directory is group- or world-writable")
            else:
                sticky_shared = bool(mode & stat.S_ISVTX and mode & 0o022 and info.st_uid in {0, uid})
                if ((uid is not None and info.st_uid not in {0, uid})
                        or (mode & 0o022 and not sticky_shared)):
                    os.close(child_fd)
                    raise ValueError("evidence path has an untrusted writable ancestor")
            os.close(current_fd)
            current_fd = child_fd
            current_path = child_path
        if not private_started:
            raise ValueError("evidence directory is outside an owner-controlled anchor")
        final_info = os.fstat(current_fd)
        final_mode = stat.S_IMODE(final_info.st_mode)
        if (not stat.S_ISDIR(final_info.st_mode)
                or (uid is not None and final_info.st_uid != uid)
                or (final_mode != 0o700 if secure else bool(final_mode & 0o022))):
            raise ValueError("evidence directory is not owner-only" if secure
                             else "credential directory has unsafe permissions")
        result = current_fd
        current_fd = -1
        return target, result
    finally:
        if current_fd >= 0:
            os.close(current_fd)

def create_private_child_directory(parent_fd, name):
    if not name or name in {".", ".."} or "/" in name:
        raise ValueError("invalid evidence directory name")
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode)
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise ValueError("new evidence directory is not owner-only")
    os.fsync(parent_fd)
    return fd

def write_private_artifact(directory_fd, name, data, run_id):
    """Durably publish one owner-only artifact without following or replacing paths."""
    if not name or name in {".", ".."} or "/" in name:
        raise ValueError("invalid evidence artifact name")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("safe no-follow evidence writes are unavailable")
    temporary = f".{name}.{run_id}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
            raise ValueError("evidence artifact is not a regular owner-owned file")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise

def read_private_artifact(directory_fd, name):
    if not name or name in {".", ".."} or "/" in name:
        raise ValueError("invalid evidence artifact name")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("evidence artifact is not a private owner-owned file")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                return b"".join(chunks)
            chunks.append(block)
    finally:
        os.close(fd)

def read_token_file(path, repo_root):
    """Read a current-owner 0600 credential without following a symlink."""
    token_path = Path(path)
    if not token_path.is_absolute():
        raise ValueError("token file path must be absolute")
    _, parent_fd = open_private_directory(
        token_path.parent, repo_root, create=False, secure=False,
    )
    try:
        fd = os.open(token_path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
                or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(fd)
            raise ValueError("token file must be a current-owner regular file with mode 0600")
        try:
            return os.read(fd, max(info.st_size, 1) + 1).decode("utf-8").strip()
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)

def reviewer_transport_environment(source=None):
    """Retain transport-only proxy and system-root CA settings, never auth/config."""
    source = os.environ if source is None else source
    environment = {name: source[name] for name in _PROXY_ENV_NAMES if name in source}
    for name in _CA_ENV_NAMES:
        value = source.get(name, "")
        if not value:
            continue
        paths = value.split(os.pathsep) if name == "SSL_CERT_DIR" else [value]
        safe = True
        for raw_path in paths:
            path = Path(raw_path)
            try:
                info = path.lstat()
            except OSError:
                safe = False
                break
            expected_type = stat.S_ISDIR(info.st_mode) if name == "SSL_CERT_DIR" else stat.S_ISREG(info.st_mode)
            if (not path.is_absolute() or stat.S_ISLNK(info.st_mode) or not expected_type
                    or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
                safe = False
                break
        if safe:
            environment[name] = value
    return environment
def auth_digest(value, secret):
    if not isinstance(secret, str) or not secret:
        raise ValueError("review authentication key is required")
    unsigned = dict(value)
    unsigned.pop("auth_hmac_sha256", None)
    return hmac.new(secret.encode("utf-8"), canon(unsigned), hashlib.sha256).hexdigest()
def sha(path): return digest(Path(path).read_bytes())
def finding(value):
    return (isinstance(value,dict) and set(value)=={"severity","title","evidence"}
            and isinstance(value.get("severity"), str)
            and value.get("severity") in {"P0","P1","P2","P3"}
            and isinstance(value.get("title"),str) and bool(value["title"])
            and isinstance(value.get("evidence"),str) and bool(value["evidence"]))
def reviewer_result(raw, *, require_dispositions=False, forbid_dispositions=False,
                    allow_summary=False, require_summary=False,
                    disposition_index_field="chunk_index"):
    try:
        value = json.loads(raw)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("invalid reviewer output") from None
    if not isinstance(value, dict):
        raise ValueError("invalid reviewer output")
    if "structured_output" in value:
        result = value["structured_output"]
    elif "result" in value:
        result = value["result"]
    else:
        result = value
    if not isinstance(result, dict):
        raise ValueError("invalid reviewer output")
    required = {"review_result", "findings"}
    allowed = required | {"dispositions"}
    if allow_summary:
        allowed.add("summary")
    if (not isinstance(result, dict) or not required <= set(result)
            or set(result) - allowed or result.get("review_result") not in {"PASS", "FAIL"}
            or not isinstance(result.get("findings"), list)
            or not all(finding(item) for item in result["findings"])):
        raise ValueError("invalid reviewer output")
    if forbid_dispositions and "dispositions" in result:
        raise ValueError("chunk reviewer output cannot contain aggregate dispositions")
    if require_dispositions and not isinstance(result.get("dispositions"), list):
        raise ValueError("aggregate reviewer omitted blocker dispositions")
    if require_summary and "summary" not in result:
        raise ValueError("aggregate group reviewer omitted its bounded summary")
    if "summary" in result and (
            not allow_summary or not isinstance(result["summary"], str)
            or len(result["summary"]) > 4000 or len(result["summary"].strip()) < 32):
        raise ValueError("invalid aggregate group summary")
    if "dispositions" in result:
        if not isinstance(result["dispositions"], list):
            raise ValueError("invalid reviewer dispositions")
        fields = {disposition_index_field, "finding_index", "source_severity", "finding_sha256",
                  "decision", "rationale"}
        for item in result["dispositions"]:
            if (not isinstance(item, dict) or set(item) != fields
                    or type(item.get(disposition_index_field)) is not int or item[disposition_index_field] < 0
                    or type(item.get("finding_index")) is not int or item["finding_index"] < 0
                    or item.get("source_severity") not in {"P0", "P1", "P2"}
                    or not isinstance(item.get("finding_sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", item["finding_sha256"]) is None
                    or item.get("decision") not in {"UPHELD", "DISPUTED"}
                    or not isinstance(item.get("rationale"), str)
                    or len(item["rationale"].strip()) < 24):
                raise ValueError("invalid reviewer dispositions")
    blocking = any(item["severity"] in {"P0", "P1", "P2"} for item in result["findings"])
    if (result["review_result"] == "PASS") != (not blocking):
        raise ValueError("reviewer verdict mismatch")
    return result


def _json_type(value):
    if value is None: return "null"
    if isinstance(value, bool): return "boolean"
    if isinstance(value, int): return "integer"
    if isinstance(value, float): return "number"
    if isinstance(value, str): return "string"
    if isinstance(value, list): return "array"
    if isinstance(value, dict): return "object"
    return "unknown"


def _safe_json_field_name(value):
    rendered = str(value)
    return rendered if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", rendered) else "<non_identifier_field>"


def _safe_json_field_names(value):
    """Bound untrusted JSON keys to safe identifier metadata."""
    if not isinstance(value, dict):
        return []
    names = sorted({_safe_json_field_name(key) for key in value})
    if len(names) > 64:
        return names[:64] + ["<additional_fields_omitted>"]
    return names


def reviewer_output_diagnostics(raw, *, require_dispositions=False,
                                forbid_dispositions=False, allow_summary=False,
                                require_summary=False,
                                disposition_index_field="chunk_index"):
    """Return bounded structural facts without retaining reviewer content."""
    diagnostic = {
        "parser_stage": "json_parse",
        "json_parse_failed": False,
        "wrapper_type": "unknown",
        "selected_wrapper": "none",
        "top_level_field_names": [],
        "structured_output_type": "unknown",
        "observed_field_names": [],
        "missing_required_fields": [],
        "unexpected_fields": [],
        "field_types": {},
        "findings_count": None,
        "invalid_finding_indexes": [],
        "dispositions_count": None,
        "invalid_disposition_indexes": [],
        "summary_present": False,
        "summary_character_length": None,
        "review_result": None,
        "reason_code": "UNKNOWN_OUTPUT_SHAPE",
    }
    try:
        value = json.loads(raw)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        diagnostic.update(json_parse_failed=True, reason_code="JSON_PARSE_FAILED")
        return diagnostic

    diagnostic["parser_stage"] = "wrapper_selection"
    diagnostic["wrapper_type"] = _json_type(value)
    diagnostic["top_level_field_names"] = _safe_json_field_names(value)
    if not isinstance(value, dict):
        diagnostic.update(structured_output_type=_json_type(value),
                           reason_code="INVALID_TOP_LEVEL_TYPE")
        return diagnostic
    if "structured_output" in value:
        result = value["structured_output"]
        diagnostic["selected_wrapper"] = "structured_output"
    elif "result" in value:
        result = value["result"]
        diagnostic["selected_wrapper"] = "result"
    else:
        result = value
        diagnostic["selected_wrapper"] = "top_level"
    diagnostic["structured_output_type"] = _json_type(result)
    if not isinstance(result, dict):
        diagnostic["reason_code"] = "INVALID_STRUCTURED_OUTPUT_TYPE"
        return diagnostic

    diagnostic["parser_stage"] = "field_validation"
    names = _safe_json_field_names(result)
    diagnostic["observed_field_names"] = names
    required = {"review_result", "findings"}
    allowed = required | {"dispositions"}
    if require_dispositions:
        required.add("dispositions")
    if allow_summary:
        allowed.add("summary")
    if require_summary:
        required.add("summary")
        allowed.add("summary")
    diagnostic["missing_required_fields"] = sorted(required - set(result))
    unexpected = sorted({_safe_json_field_name(key) for key in result if key not in allowed})
    diagnostic["unexpected_fields"] = (
        unexpected[:64] + ["<additional_fields_omitted>"]
        if len(unexpected) > 64 else unexpected
    )
    for key in result:
        safe_key = _safe_json_field_name(key)
        if safe_key not in diagnostic["field_types"] and len(diagnostic["field_types"]) < 64:
            diagnostic["field_types"][safe_key] = _json_type(result[key])
    if len(result) > len(diagnostic["field_types"]):
        diagnostic["field_types"]["<additional_fields_omitted>"] = "unknown"
    if diagnostic["missing_required_fields"]:
        diagnostic["reason_code"] = "MISSING_REQUIRED_FIELD"
        return diagnostic
    if diagnostic["unexpected_fields"]:
        diagnostic["reason_code"] = "UNEXPECTED_FIELDS"
        return diagnostic

    verdict = result.get("review_result")
    diagnostic["review_result"] = verdict if (
        isinstance(verdict, str) and verdict in {"PASS", "FAIL"}
    ) else (
        "INVALID" if verdict is not None else None
    )
    if not isinstance(verdict, str) or verdict not in {"PASS", "FAIL"}:
        diagnostic["reason_code"] = "INVALID_REVIEW_RESULT"
        return diagnostic
    findings = result.get("findings")
    if not isinstance(findings, list):
        diagnostic["reason_code"] = "INVALID_FINDINGS_TYPE"
        return diagnostic
    diagnostic["findings_count"] = len(findings)
    invalid_findings = [index for index, item in enumerate(findings) if not finding(item)]
    diagnostic["invalid_finding_indexes"] = invalid_findings[:64]
    if invalid_findings:
        diagnostic["reason_code"] = "INVALID_FINDING_SHAPE"
        diagnostic["parser_stage"] = "finding_validation"
        return diagnostic
    if forbid_dispositions and "dispositions" in result:
        diagnostic["reason_code"] = "UNEXPECTED_DISPOSITIONS"
        return diagnostic

    dispositions = result.get("dispositions")
    if "dispositions" in result:
        if not isinstance(dispositions, list):
            diagnostic["reason_code"] = "INVALID_DISPOSITIONS_TYPE"
            return diagnostic
        diagnostic["dispositions_count"] = len(dispositions)
        expected_fields = {
            disposition_index_field, "finding_index", "source_severity",
            "finding_sha256", "decision", "rationale",
        }
        invalid = []
        for index, item in enumerate(dispositions):
            source_severity = item.get("source_severity") if isinstance(item, dict) else None
            decision = item.get("decision") if isinstance(item, dict) else None
            if (not isinstance(item, dict) or set(item) != expected_fields
                    or type(item.get(disposition_index_field)) is not int
                    or item[disposition_index_field] < 0
                    or type(item.get("finding_index")) is not int
                    or item["finding_index"] < 0
                    or not isinstance(source_severity, str)
                    or source_severity not in {"P0", "P1", "P2"}
                    or not isinstance(item.get("finding_sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", item["finding_sha256"]) is None
                    or not isinstance(decision, str)
                    or decision not in {"UPHELD", "DISPUTED"}
                    or not isinstance(item.get("rationale"), str)
                    or len(item["rationale"].strip()) < 24):
                invalid.append(index)
        diagnostic["invalid_disposition_indexes"] = invalid[:64]
        if invalid:
            diagnostic["reason_code"] = "INVALID_DISPOSITION_SHAPE"
            diagnostic["parser_stage"] = "disposition_validation"
            return diagnostic
    if require_dispositions and not isinstance(dispositions, list):
        diagnostic["reason_code"] = "INVALID_DISPOSITIONS_TYPE"
        return diagnostic

    summary = result.get("summary")
    diagnostic["summary_present"] = "summary" in result
    if "summary" in result:
        if not allow_summary or not isinstance(summary, str):
            diagnostic["reason_code"] = "INVALID_SUMMARY_TYPE"
            return diagnostic
        diagnostic["summary_character_length"] = len(summary)
        if len(summary) > 4000:
            diagnostic["reason_code"] = "SUMMARY_TOO_LONG"
            return diagnostic
        if len(summary.strip()) < 32:
            diagnostic["reason_code"] = "SUMMARY_TOO_SHORT"
            return diagnostic
    blocking = any(item["severity"] in {"P0", "P1", "P2"} for item in findings)
    if (verdict == "PASS") != (not blocking):
        diagnostic["reason_code"] = "VERDICT_MISMATCH"
        return diagnostic
    diagnostic["parser_stage"] = "complete"
    diagnostic["reason_code"] = "VALID"
    return diagnostic


def validate_blocker_dispositions(chunks_, aggregate_result, *, allow_disputes=True,
                                  source_index_field="chunk_index"):
    """Require an auditable aggregate decision for every blocking chunk finding."""
    expected = {}
    for chunk in chunks_:
        chunk_index = chunk["index"]
        for finding_index, item in enumerate(chunk["result"]["findings"]):
            if item["severity"] in {"P0", "P1", "P2"}:
                expected[(chunk_index, finding_index)] = item

    observed = {}
    for item in aggregate_result.get("dispositions", []):
        identity = (item[source_index_field], item["finding_index"])
        source = expected.get(identity)
        if source is None:
            raise ValueError("aggregate disposition refers to no blocking chunk finding")
        if identity in observed:
            raise ValueError("aggregate duplicated a blocking finding disposition")
        if (item["source_severity"] != source["severity"]
                or item["finding_sha256"] != digest(canon(source))):
            raise ValueError("aggregate disposition does not bind the chunk finding")
        if item["decision"] == "UPHELD" and source not in aggregate_result["findings"]:
            raise ValueError("aggregate omitted an upheld blocking chunk finding")
        if item["decision"] == "DISPUTED" and source in aggregate_result["findings"]:
            raise ValueError("aggregate both disputed and upheld the same chunk finding")
        if not allow_disputes and item["decision"] != "UPHELD":
            raise ValueError("final synthesis cannot dispute a bounded group finding")
        observed[identity] = item
    if set(observed) != set(expected):
        raise ValueError("aggregate omitted a blocking chunk finding disposition")


def indexed_chunk_findings(chunks_, *, source_index_field="chunk_index"):
    """Build the aggregate's indexed findings and precomputed blocker hashes."""
    all_findings = []
    required_dispositions = []
    for chunk in chunks_:
        for finding_index, item in enumerate(chunk["result"]["findings"]):
            all_findings.append({
                source_index_field: chunk["index"],
                "finding_index": finding_index,
                "finding": item,
            })
            if item["severity"] in {"P0", "P1", "P2"}:
                required_dispositions.append({
                    source_index_field: chunk["index"],
                    "finding_index": finding_index,
                    "source_severity": item["severity"],
                    "finding_sha256": digest(canon(item)),
                })
    return all_findings, required_dispositions


def git(root, *args):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(root), *args],
        env=_GIT_ENV,
    )
def full_sha(value):
    if len(value) != 40 or any(c not in "0123456789abcdef" for c in value.lower()): raise ValueError("full SHA required")
    return value.lower()

def repository_identity(remote):
    """Return a credential-free identity for a Git remote URL."""
    if not isinstance(remote, str) or not remote.strip():
        raise ValueError("repository remote is empty")
    value = remote.strip()
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("repository remote has no host")
        host = hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port is not None:
            host += f":{parsed.port}"
        path = parsed.path.split("?", 1)[0].split("#", 1)[0]
        return f"{parsed.scheme.lower()}://{host}{path}"
    # Git's scp-like SSH spelling is [user@]host:path.  Drop the user and
    # reject an at-sign in the path so malformed credential-like input cannot
    # be copied into a receipt.
    match = re.fullmatch(r"(?:(?:[^/@:]+)@)?([^/:]+):([^?#]+)(?:[?#].*)?", value)
    if match:
        host, path = match.groups()
        if "@" in path:
            raise ValueError("repository remote cannot be sanitized")
        return f"ssh://{host.lower()}/{path.lstrip('/')}"
    if "@" in value:
        raise ValueError("repository remote cannot be sanitized")
    return value.split("?", 1)[0].split("#", 1)[0]

def trusted_path_owner(info):
    uid = os.getuid() if hasattr(os, "getuid") else info.st_uid
    return info.st_uid in {0, uid}

def trusted_path_mode(info):
    return trusted_path_owner(info) and not (stat.S_IMODE(info.st_mode) & 0o022)

def trusted_directory(path):
    try:
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_dir():
            return False
        for directory in (resolved, *resolved.parents):
            info = directory.stat()
            if not stat.S_ISDIR(info.st_mode) or not trusted_path_mode(info):
                return False
        return True
    except OSError:
        return False

def trusted_executable(path):
    try:
        resolved = Path(path).resolve(strict=True)
        info = resolved.stat()
        return (stat.S_ISREG(info.st_mode) and trusted_path_mode(info)
                and os.access(resolved, os.X_OK) and trusted_directory(resolved.parent))
    except OSError:
        return False

def chunks(diff):
    if not diff: raise ValueError("empty diff is not reviewable")
    out=[]; start=0
    while start < len(diff):
        end=min(len(diff),start+CHUNK_BYTES); cut=diff.rfind(b"\n",start+1,end+1)
        if cut > start: end=cut+1
        source=diff[start:end]; out.append({"index":len(out),"start":start,"end":end,"sha256":digest(source)}) ; start=end
    return out

def aggregate_group_layout(plan):
    """Partition consecutive reviewed chunks into deterministic bounded groups."""
    groups=[]; current=[]
    for chunk in plan:
        if current and chunk["end"] - current[0]["start"] > AGGREGATE_GROUP_BYTES:
            first,last=current[0],current[-1]
            groups.append({"index":len(groups),"start":first["start"],"end":last["end"],
                           "chunk_indexes":[item["index"] for item in current]})
            current=[]
        current.append(chunk)
    if current:
        first,last=current[0],current[-1]
        groups.append({"index":len(groups),"start":first["start"],"end":last["end"],
                       "chunk_indexes":[item["index"] for item in current]})
    return groups

def aggregate_groups(diff, plan):
    """Bind each deterministic group to its exact byte range."""
    return [{**group,"sha256":digest(diff[group["start"]:group["end"]])}
            for group in aggregate_group_layout(plan)]

def aggregate_group_manifest_hash(base, head, diff_hash, manifest_hash, groups):
    descriptors=[{key:group[key] for key in ("index","start","end","chunk_indexes","sha256")}
                 for group in groups]
    manifest={"version":"cmh-deepseek-aggregate-groups/v1","base_sha":base,
              "head_sha":head,"diff_sha256":diff_hash,"chunk_manifest_sha256":manifest_hash,
              "groups":descriptors}
    return digest(canon(manifest))

def validate(receipt, base, head, root=None, receipt_path=None, mission_id=None, repository=None, secret=None):
    required={"version","repository","mission_id","base_sha","head_sha","diff_sha256","manifest_sha256","group_manifest_sha256","chunks","groups","chunk_findings","aggregate_result","aggregate_output_sha256","provider","model","command_sha256","review_result","findings","integrity_sha256","auth_hmac_sha256"}
    optional={"started_at","completed_at"}
    if not isinstance(receipt,dict) or not required <= set(receipt) or set(receipt)-required-optional: raise ValueError("incomplete or unknown receipt fields")
    if receipt["version"] != VERSION or receipt["base_sha"] != base or receipt["head_sha"] != head: raise ValueError("receipt exact-head binding mismatch")
    if not isinstance(receipt["repository"],str) or not receipt["repository"] or not isinstance(receipt["mission_id"],str) or not receipt["mission_id"]: raise ValueError("invalid receipt identity")
    if repository_identity(receipt["repository"]) != receipt["repository"]: raise ValueError("receipt repository identity is not canonical")
    if mission_id is not None and receipt["mission_id"] != mission_id: raise ValueError("receipt mission binding mismatch")
    if repository is not None and receipt["repository"] != repository_identity(repository): raise ValueError("receipt repository binding mismatch")
    copy=dict(receipt); observed=copy.pop("integrity_sha256"); copy.pop("auth_hmac_sha256", None)
    if digest(canon(copy)) != observed: raise ValueError("receipt integrity mismatch")
    if not isinstance(receipt["auth_hmac_sha256"],str) or len(receipt["auth_hmac_sha256"]) != 64:
        raise ValueError("review authentication evidence is incomplete")
    if not hmac.compare_digest(receipt["auth_hmac_sha256"], auth_digest(receipt, secret)):
        raise ValueError("review authentication evidence mismatch")
    if (receipt["provider"] != "deepseek" or receipt["model"] != MODEL
            or not isinstance(receipt["command_sha256"],str) or len(receipt["command_sha256"])!=64): raise ValueError("reviewer provenance mismatch")
    chunks_=receipt["chunks"]
    if not isinstance(chunks_,list) or not chunks_ or [c.get("index") for c in chunks_ if isinstance(c,dict)] != list(range(len(chunks_))): raise ValueError("missing or duplicate chunks")
    position=0; chunk_findings=[]; descriptors=[]
    for chunk in chunks_:
        start,end=chunk.get("start"),chunk.get("end"); result=chunk.get("result")
        if not isinstance(start,int) or not isinstance(end,int) or start!=position or end<=start: raise ValueError("invalid chunk coverage")
        if not isinstance(chunk.get("sha256"),str) or len(chunk["sha256"])!=64: raise ValueError("invalid chunk identity")
        if not isinstance(chunk.get("output_sha256"),str) or len(chunk["output_sha256"])!=64: raise ValueError("invalid chunk output identity")
        reviewer_result(json.dumps(result), forbid_dispositions=True)
        descriptors.append({"index":chunk["index"],"start":start,"end":end,"sha256":chunk["sha256"]})
        chunk_findings.extend(result["findings"]); position=end
    if chunk_findings != receipt["chunk_findings"]: raise ValueError("chunk findings mismatch")
    groups=receipt["groups"]
    if not isinstance(groups,list) or not groups: raise ValueError("missing aggregate groups")
    expected_groups=aggregate_group_layout(descriptors)
    if len(groups)!=len(expected_groups): raise ValueError("aggregate group coverage mismatch")
    group_results=[]; group_descriptors=[]
    for index,(group,expected) in enumerate(zip(groups,expected_groups)):
        if (not isinstance(group,dict)
                or set(group)!={"index","start","end","chunk_indexes","sha256","output_sha256","result"}
                or any(group.get(key)!=expected[key] for key in ("index","start","end","chunk_indexes"))
                or not isinstance(group.get("sha256"),str) or len(group["sha256"])!=64
                or not isinstance(group.get("output_sha256"),str) or len(group["output_sha256"])!=64):
            raise ValueError("aggregate group coverage or identity mismatch")
        group_result=reviewer_result(json.dumps(group["result"]),require_dispositions=True,
                                     allow_summary=True,require_summary=True)
        selected_chunks=[chunks_[chunk_index] for chunk_index in expected["chunk_indexes"]]
        validate_blocker_dispositions(selected_chunks,group_result)
        group_results.append({"index":index,"result":group_result})
        group_descriptors.append({key:group[key] for key in
                                  ("index","start","end","chunk_indexes","sha256")})
    expected_group_manifest={"version":"cmh-deepseek-aggregate-groups/v1",
                             "base_sha":base,"head_sha":head,
                             "diff_sha256":receipt["diff_sha256"],
                             "chunk_manifest_sha256":receipt["manifest_sha256"],
                             "groups":group_descriptors}
    if digest(canon(expected_group_manifest))!=receipt["group_manifest_sha256"]:
        raise ValueError("aggregate group manifest hash mismatch")
    aggregate_result = reviewer_result(
        json.dumps(receipt["aggregate_result"]), require_dispositions=True,
        disposition_index_field="group_index",
    )
    if not isinstance(receipt["aggregate_output_sha256"], str) or len(receipt["aggregate_output_sha256"]) != 64:
        raise ValueError("aggregate output identity is incomplete")
    if receipt["review_result"] != aggregate_result["review_result"]:
        raise ValueError("aggregate verdict mismatch")
    # The final cross-group synthesis has only bounded group summaries, so it
    # must carry every group blocker forward rather than disputing source it did
    # not receive. Group reviewers can dispute chunk findings after seeing source.
    validate_blocker_dispositions(group_results, aggregate_result,allow_disputes=False,
                                  source_index_field="group_index")
    if aggregate_result["findings"] != receipt["findings"]:
        raise ValueError("aggregate findings mismatch")
    if root is not None:
        diff=git(Path(root).resolve(),"diff","--no-ext-diff","--no-textconv","--binary",f"{base}..{head}")
        if position!=len(diff) or digest(diff)!=receipt["diff_sha256"]: raise ValueError("receipt diff coverage mismatch")
        if descriptors!=chunks(diff): raise ValueError("chunk manifest does not match exact diff")
        manifest={"version":"cmh-deepseek-chunks/v2","base_sha":base,"head_sha":head,"diff_sha256":digest(diff),"chunks":descriptors}
        if digest(canon(manifest))!=receipt["manifest_sha256"]: raise ValueError("chunk manifest hash mismatch")
        expected_group_sources=aggregate_groups(diff,descriptors)
        for observed,expected in zip(groups,expected_group_sources):
            if observed["sha256"]!=expected["sha256"]:
                raise ValueError("aggregate group source hash mismatch")
        if receipt_path is not None:
            evidence=Path(os.path.abspath(receipt_path)).parent
            evidence_fd=None
            try:
                _, evidence_fd=open_private_directory(evidence, root)
                for chunk in chunks_:
                    artifact=read_private_artifact(evidence_fd,f"chunk-{chunk['index']:03d}.json")
                    if digest(artifact)!=chunk["output_sha256"]: raise ValueError("chunk artifact mismatch")
                    if reviewer_result(artifact.decode("utf-8"), forbid_dispositions=True)!=chunk["result"]: raise ValueError("chunk result does not match durable artifact")
                for group in groups:
                    artifact=read_private_artifact(evidence_fd,f"group-{group['index']:03d}.json")
                    if digest(artifact)!=group["output_sha256"]: raise ValueError("aggregate group artifact mismatch")
                    if reviewer_result(artifact.decode("utf-8"),require_dispositions=True,
                                       allow_summary=True,require_summary=True)!=group["result"]:
                        raise ValueError("aggregate group result does not match durable artifact")
                aggregate_artifact=read_private_artifact(evidence_fd,"aggregate.json")
                if digest(aggregate_artifact) != receipt["aggregate_output_sha256"]:
                    raise ValueError("aggregate artifact mismatch")
                if reviewer_result(aggregate_artifact.decode("utf-8"), require_dispositions=True,
                                   disposition_index_field="group_index") != aggregate_result:
                    raise ValueError("aggregate result does not match durable artifact")
            finally:
                if evidence_fd is not None: os.close(evidence_fd)
    if receipt["review_result"] not in {"PASS", "FAIL"}:
        raise ValueError("invalid aggregate verdict")
    blocking=any(f.get("severity") in {"P0","P1","P2"} for f in receipt["findings"])
    if (receipt["review_result"] == "PASS") != (not blocking): raise ValueError("aggregate verdict mismatch")
    return receipt
def prompt(base, head, diff_hash, manifest_hash, chunk, source):
    try: rendered="UTF-8 DIFF:\n"+source.decode("utf-8")
    except UnicodeDecodeError: rendered="BASE64-ENCODED EXACT DIFF BYTES:\n"+base64.b64encode(source).decode("ascii")
    return ("You are an independent restricted code reviewer. Do not use tools or filesystem. Return only JSON matching the schema. "
            "PASS only when P0/P1/P2 are absent.\n"
            f"Base={base}\nHead={head}\nDiffSHA256={diff_hash}\nManifestSHA256={manifest_hash}\n"
            f"Chunk={chunk['index']} range={chunk['start']}:{chunk['end']} SHA256={chunk['sha256']}\n"+rendered)

def aggregate_group_prompt(base, head, diff_hash, manifest_hash, group_manifest_hash,
                           group, plan, source, chunk_findings, required_dispositions):
    """Review a bounded exact-source range and reconcile its underlying chunks."""
    try: rendered = "UTF-8 EXACT GROUP DIFF:\n" + source.decode("utf-8")
    except UnicodeDecodeError: rendered = "BASE64-ENCODED EXACT GROUP DIFF BYTES:\n" + base64.b64encode(source).decode("ascii")
    group_chunks=[chunk for chunk in plan if chunk["index"] in group["chunk_indexes"]]
    return ("You are an independent synthesis reviewer for one bounded source group. Do not use tools or filesystem. "
            "Review the exact group source and interactions among every included chunk. Return only JSON matching the schema. "
            "PASS only when P0/P1/P2 are absent. Account for every P0/P1/P2 chunk finding in dispositions. "
            "Copy each chunk_index, finding_index, source_severity, and finding_sha256 exactly from RequiredDispositions; "
            "do not calculate, modify, omit, or duplicate these values. Use UPHELD when valid and include the exact finding; "
            "use DISPUTED only when this group's complete source disproves it, with a specific rationale. "
            "Always emit all four required top-level fields: review_result, findings, dispositions, and summary. "
            "If RequiredDispositions is empty, dispositions must still be present as an empty array []. "
            "summary is mandatory and must be 32 to 4000 characters. Write a concise summary of edited files, changed interfaces/data/control flows, "
            "state transitions, and relevant dependencies so a later cross-group reviewer can compare interactions.\n"
            f"Base={base}\nHead={head}\nDiffSHA256={diff_hash}\nChunkManifestSHA256={manifest_hash}\n"
            f"GroupManifestSHA256={group_manifest_hash}\nGroupIndex={group['index']} "
            f"ChunkIndexes={json.dumps(group['chunk_indexes'])} Range={group['start']}:{group['end']} "
            f"GroupDiffSHA256={group['sha256']}\n"
            f"ChunkDescriptors={json.dumps(group_chunks,sort_keys=True)}\n"
            f"ChunkFindings={json.dumps(chunk_findings,sort_keys=True)}\n"
            f"RequiredDispositions={json.dumps(required_dispositions,sort_keys=True)}\n"+rendered)

def aggregate_prompt(base, head, diff_hash, manifest_hash, group_manifest_hash,
                     groups, group_findings, required_dispositions):
    """Synthesize cross-group interactions without resending the unbounded diff."""
    summaries=[{"group_index":group["index"],"start":group["start"],"end":group["end"],
                "chunk_indexes":group["chunk_indexes"],"group_sha256":group["sha256"],
                "output_sha256":group["output_sha256"],"summary":group["result"]["summary"],
                "review_result":group["result"]["review_result"],
                "findings":group["result"]["findings"]} for group in groups]
    return ("You are the final cross-group independent reviewer for this exact diff. Do not use tools or filesystem. "
            "The diff was partitioned into non-overlapping source groups, each reviewed with its exact source by an independent pass. "
            "Compare all group summaries for cross-file/cross-group interactions, including API/data contracts, state transitions, "
            "error handling, and security boundaries; add findings for risks visible only across groups. "
            "Return only JSON matching the schema. PASS only when P0/P1/P2 are absent. "
            "Account for every P0/P1/P2 group finding in dispositions. Copy each group_index, finding_index, source_severity, "
            "and finding_sha256 exactly from RequiredDispositions; do not modify or omit them. Mark every supplied group blocker UPHELD "
            "and include its exact finding in findings; this synthesis does not have the source needed to dispute one. "
            "PASS is allowed only when findings contain no P0/P1/P2.\n"
            f"Base={base}\nHead={head}\nDiffSHA256={diff_hash}\nChunkManifestSHA256={manifest_hash}\n"
            f"GroupManifestSHA256={group_manifest_hash}\nGroupCount={len(groups)}\n"
            f"GroupFindings={json.dumps(group_findings,sort_keys=True)}\n"
            f"RequiredDispositions={json.dumps(required_dispositions,sort_keys=True)}\n"
            f"ReviewedGroupSummaries={json.dumps(summaries,sort_keys=True)}")

def reviewer_group_result(raw):
    return reviewer_result(raw,require_dispositions=True,allow_summary=True,require_summary=True)

def bounded_prompt_bytes(prompt_text):
    rendered=prompt_text.encode("utf-8")
    if len(rendered)>MAX_REVIEW_PROMPT_BYTES:
        raise ValueError("review request exceeds the configured bounded prompt size")
    return rendered

def invoke_reviewer(command, prompt_text, env, timeout):
    # Keep source and synthesis prompts on stdin, not argv. The bounded request
    # limit is enforced before this call, independently of the operating system's
    # argv limit. Claude Code print mode supports prompts on stdin.
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, start_new_session=True)
    try:
        stdout, stderr = process.communicate(prompt_text.encode("utf-8"), timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        pgid = os.getpgid(process.pid)
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr) from exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


class ReviewAttemptFailure(RuntimeError):
    """Safe typed failure raised only after publishing durable attempt evidence."""

    def __init__(self, details, evidence_path=None, evidence_sha256=None):
        self.classification = details.classification
        self.retryable = details.retryable
        self.reason_code = details.reason_code
        self.diagnostic = details.sanitized_diagnostic
        self.evidence_path = str(evidence_path) if evidence_path is not None else None
        self.evidence_sha256 = evidence_sha256
        super().__init__(
            f"DeepSeek review attempt failed: {self.classification.value}; "
            f"retryable={str(self.retryable).lower()}"
        )

    def as_payload(self):
        """Return the bounded machine-readable failure contract for callers."""
        return {
            "status": "BLOCKED_EXTERNAL",
            "error": self.diagnostic,
            "failure_classification": self.classification.value,
            "retryable": self.retryable,
            "reason_code": self.reason_code,
            "failure_evidence_path": self.evidence_path,
            "failure_evidence_sha256": self.evidence_sha256,
        }


def _captured_bytes(value):
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", errors="replace")


def _captured_text(value):
    return _captured_bytes(value).decode("utf-8", errors="replace")


def _credential_echoed(stdout, stderr, token):
    if not token:
        return False
    secret = token.encode("utf-8")
    return any(secret in _captured_bytes(value) for value in (stdout, stderr))


def _output_failure_details(error):
    """Map local output validation errors without retaining their raw text."""
    message = str(error).casefold()
    if any(marker in message for marker in (
            "disposition", "review contract", "verdict mismatch", "cannot dispute")):
        return ReviewFailureDetails(
            ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
            "review_contract_rejected",
            "reviewer output violated the required review contract",
        )
    return ReviewFailureDetails(
        ReviewFailureClassification.INVALID_REVIEWER_OUTPUT,
        "invalid_reviewer_output",
        "reviewer response did not match the required output schema",
    )


_RETRYABLE_GROUP_OUTPUT_FORMAT_CODES = {
    "JSON_PARSE_FAILED", "INVALID_TOP_LEVEL_TYPE", "INVALID_STRUCTURED_OUTPUT_TYPE",
    "MISSING_REQUIRED_FIELD", "UNEXPECTED_FIELDS", "INVALID_REVIEW_RESULT",
    "INVALID_FINDINGS_TYPE", "INVALID_FINDING_SHAPE", "INVALID_DISPOSITIONS_TYPE",
    "INVALID_DISPOSITION_SHAPE", "INVALID_SUMMARY_TYPE", "SUMMARY_TOO_SHORT",
    "SUMMARY_TOO_LONG",
}


def _group_output_failure_details(diagnostic, *, retry_exhausted=False):
    """Classify one successful-process group response from safe shape facts."""
    reason = diagnostic.get("reason_code") if isinstance(diagnostic, dict) else None
    if reason in _RETRYABLE_GROUP_OUTPUT_FORMAT_CODES:
        if retry_exhausted:
            return ReviewFailureDetails(
                ReviewFailureClassification.INVALID_REVIEWER_OUTPUT,
                "structured_output_retry_exhausted",
                "group reviewer output remained structurally invalid after the bounded format retry",
            )
        return ReviewFailureDetails(
            ReviewFailureClassification.TRANSIENT_STRUCTURED_OUTPUT_FORMAT_FAILURE,
            f"structured_output_{reason.casefold()}",
            f"group reviewer output format was invalid ({reason})",
        )
    if reason == "VERDICT_MISMATCH":
        return ReviewFailureDetails(
            ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
            "review_contract_rejected",
            "reviewer output verdict conflicts with its findings",
        )
    if reason in {"VALID", None}:
        return ReviewFailureDetails(
            ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
            "review_contract_rejected",
            "reviewer output violated blocker disposition requirements",
        )
    return ReviewFailureDetails(
        ReviewFailureClassification.INVALID_REVIEWER_OUTPUT,
        f"structured_output_{str(reason).casefold()}",
        f"group reviewer output failed validation ({reason})",
    )


def _publish_group_output_attempt(
        *, evidence_fd, run_id, repository, mission_id, base, head, diff_hash,
        group, prompt_text, command, diagnostic, attempt_index, retry_scheduled,
        stdout, stderr, details):
    """Persist structural metadata only; raw model output is never written."""
    record = {
        "schema_version": "cmh-deepseek-group-output-attempt/v1",
        "repository": repository,
        "mission_id": mission_id,
        "base_sha": base,
        "head_sha": head,
        "diff_sha256": diff_hash,
        "stage": "aggregate_group",
        "group_index": group["index"],
        "group_source_sha256": group["sha256"],
        "attempt_index": attempt_index,
        "failure_classification": details.classification.value,
        "retryable": details.retryable,
        "sanitized_diagnostic": details.sanitized_diagnostic,
        "retry_scheduled": retry_scheduled,
        "retry_limit": GROUP_OUTPUT_FORMAT_RETRY_LIMIT,
        "reason_code": diagnostic.get("reason_code"),
        "structural_diagnostics": diagnostic,
        "prompt_bytes": len(prompt_text.encode("utf-8")),
        "prompt_sha256": digest(prompt_text.encode("utf-8")),
        "command_sha256": digest(canon(command)),
        "process_stdout_sha256": digest(_captured_bytes(stdout)),
        "process_stderr_sha256": digest(_captured_bytes(stderr)),
        "receipt_written": False,
    }
    record["integrity_sha256"] = digest(canon(record))
    rendered = canon(record) + b"\n"
    name = f"group-{group['index']:03d}-output-attempt-{attempt_index}.json"
    write_private_artifact(evidence_fd, name, rendered, run_id)
    return name, digest(rendered)


def _publish_attempt_failure(
        *, evidence_fd, evidence_dir, run_id, repository, mission_id, base, head, diff_hash,
        stage, chunk_index, started_at, completed_at, terminal_status, exit_code,
        command, stdout, stderr, token, details=None, completed_chunks=(),
        group_index=None, completed_groups=(), group_output_attempts=()):
    """Commit one sanitized typed failure artifact; never persist raw streams."""
    stdout_bytes = _captured_bytes(stdout)
    stderr_bytes = _captured_bytes(stderr)
    if _credential_echoed(stdout, stderr, token):
        details = ReviewFailureDetails(
            ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
            "credential_echo_detected",
            "reviewer output contained the configured credential; raw output discarded",
        )
    elif details is None:
        details = classify_process_failure((
            _captured_text(stdout), _captured_text(stderr),
        ))

    completed_artifacts = [
        {
            "chunk_index": chunk.get("index"),
            "path": f"chunk-{chunk.get('index', 0):03d}.json",
            "sha256": chunk.get("output_sha256"),
        }
        for chunk in completed_chunks
        if isinstance(chunk, dict) and isinstance(chunk.get("output_sha256"), str)
    ]
    completed_group_artifacts = [
        {
            "group_index": group.get("index"),
            "path": f"group-{group.get('index', 0):03d}.json",
            "sha256": group.get("output_sha256"),
        }
        for group in completed_groups
        if isinstance(group, dict) and isinstance(group.get("output_sha256"), str)
    ]
    record = {
        "schema_version": "cmh-review-attempt-failure/v1",
        "repository": repository,
        "mission_id": mission_id,
        "base_sha": base,
        "head_sha": head,
        "diff_sha256": diff_hash,
        "reviewer": "deepseek",
        "provider": "deepseek",
        "model": MODEL,
        "reasoning_effort": None,
        "attempt_id": run_id,
        "stage": stage,
        "chunk_index": chunk_index,
        "group_index": group_index,
        "terminal_status": terminal_status,
        "exit_code": exit_code,
        "process_succeeded": exit_code == 0,
        "failure_phase": (
            "PROCESS_OR_PROVIDER" if terminal_status != "OUTPUT_REJECTED" or exit_code != 0
            else "STRUCTURED_OUTPUT_VALIDATION" if details.classification in {
                ReviewFailureClassification.INVALID_REVIEWER_OUTPUT,
                ReviewFailureClassification.TRANSIENT_STRUCTURED_OUTPUT_FORMAT_FAILURE,
            } else "REVIEW_CONTRACT_VALIDATION"
        ),
        "turn_completed": None,
        "started_at": started_at,
        "completed_at": completed_at,
        "failure_classification": details.classification.value,
        "retryable": details.retryable,
        "reason_code": details.reason_code,
        "http_status": details.http_status,
        "provider_error_code": details.provider_error_code,
        "sanitized_diagnostic": details.sanitized_diagnostic,
        "process_stdout_sha256": digest(stdout_bytes),
        "process_stderr_sha256": digest(stderr_bytes),
        "command_sha256": digest(canon(command)) if command else None,
        "completed_chunk_artifacts": completed_artifacts,
        "completed_group_artifacts": completed_group_artifacts,
        "group_output_attempt_artifacts": list(group_output_attempts),
        "receipt_written": False,
    }
    record["integrity_sha256"] = digest(canon(record))
    rendered = canon(record) + b"\n"
    if chunk_index is not None:
        stage_name = f"{stage}-{chunk_index:03d}"
    elif group_index is not None:
        stage_name = f"{stage}-{group_index:03d}"
    else:
        stage_name = stage
    name = f"review-attempt-failure-{stage_name}-{run_id}.json"
    try:
        write_private_artifact(evidence_fd, name, rendered, run_id)
    except (OSError, ValueError):
        failed_details = ReviewFailureDetails(
            ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE,
            "failure_evidence_persistence_failed",
            "typed reviewer failure evidence could not be persisted",
        )
        raise ReviewAttemptFailure(failed_details) from None
    return ReviewAttemptFailure(details, evidence_dir / name, digest(rendered))


def _raise_attempt_failure(**kwargs):
    raise _publish_attempt_failure(**kwargs)


def reject_credential_echo(completed, token):
    """Reject secrets on either captured stream without reflecting the stream."""
    if _credential_echoed(completed.stdout, completed.stderr, token):
        raise ValueError("DeepSeek output contained review credential")

def resolve_claude_launcher(root, path_value):
    """Resolve the owner-installed CLI without searching the reviewed tree or CWD."""
    repository=Path(root).resolve()
    safe_entries=[]
    for entry in path_value.split(os.pathsep):
        if not entry:
            continue
        candidate=Path(entry)
        if not candidate.is_absolute():
            continue
        try:
            directory=candidate.resolve(strict=True)
        except OSError:
            continue
        if (not directory.is_dir() or not trusted_directory(directory)
                or directory==repository or directory in repository.parents
                or repository in directory.parents):
            continue
        rendered=str(directory)
        if rendered not in safe_entries:
            safe_entries.append(rendered)
    safe_path=os.pathsep.join(safe_entries)
    if not safe_entries:
        raise ValueError("trusted absolute Claude Code launcher is unavailable")
    executable=shutil.which("claude",path=safe_path)
    if not executable or not Path(executable).is_absolute():
        raise ValueError("trusted absolute Claude Code launcher is unavailable")
    try:
        resolved=Path(executable).resolve(strict=True)
    except OSError as exc:
        raise ValueError("trusted absolute Claude Code launcher is unavailable") from exc
    if (not trusted_executable(resolved)
            or resolved==repository or repository in resolved.parents):
        raise ValueError("Claude Code launcher is not trusted outside the reviewed repository")
    return str(resolved),safe_path

def run(args):
    root = Path(args.repo).resolve()
    base = full_sha(args.base)
    head = full_sha(args.head)
    if git(root, "rev-parse", "HEAD").decode().strip().lower() != head:
        raise ValueError("worktree HEAD differs from requested HEAD")
    repository = repository_identity(git(root, "config", "--get", "remote.origin.url").decode().strip())
    diff = git(root, "diff", "--no-ext-diff", "--no-textconv", "--binary", f"{base}..{head}")
    plan = chunks(diff)
    diff_hash = digest(diff)
    manifest = {
        "version": "cmh-deepseek-chunks/v2", "base_sha": base, "head_sha": head,
        "diff_sha256": diff_hash, "chunks": [dict(chunk) for chunk in plan],
    }
    manifest_hash = digest(canon(manifest))

    evidence_root_fd = None
    evidence_fd = None
    settings = None
    env = {}
    token = ""
    try:
        evidence_root, evidence_root_fd = open_private_directory(args.evidence, root)
        run_id = uuid.uuid4().hex
        evidence = evidence_root / run_id
        evidence_fd = create_private_child_directory(evidence_root_fd, run_id)
        run_started_at = time.time()

        try:
            claude_executable, safe_path = resolve_claude_launcher(
                root, os.environ.get("PATH", ""),
            )
            token = read_token_file(args.token_file, root)
            if not token:
                raise ValueError("empty DeepSeek token file")
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            message = str(exc).casefold()
            if "token" in message or "authentication" in message:
                details = ReviewFailureDetails(
                    ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                    "reviewer_credential_policy_failure",
                    "reviewer credential file is missing or violates its security policy",
                )
            else:
                details = ReviewFailureDetails(
                    ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                    "trusted_reviewer_launcher_unavailable",
                    "trusted DeepSeek reviewer executable could not be resolved",
                )
            _raise_attempt_failure(
                evidence_fd=evidence_fd, evidence_dir=evidence, run_id=run_id,
                repository=repository, mission_id=args.mission_id, base=base, head=head,
                diff_hash=diff_hash, stage="setup", chunk_index=None,
                started_at=run_started_at, completed_at=time.time(),
                terminal_status="NOT_STARTED", exit_code=None, command=None,
                stdout="", stderr="", token="", details=details,
            )

        settings = tempfile.NamedTemporaryFile(mode="w", delete=False)
        settings.write(
            '{"permissions":{"allow":[],"deny":["Bash","Edit","Write","Read",'
            '"Glob","Grep","WebFetch","WebSearch"]}}'
        )
        settings.close()
        common_command = [
            claude_executable, "--bare", "--restricted", "--print", "--model", MODEL,
            "--settings", settings.name, "--tools", "", "--disallowed-tools",
            "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch", "--output-format", "json",
        ]
        chunk_command = common_command + [
            "--json-schema", json.dumps(CHUNK_SCHEMA, separators=(",", ":")),
        ]
        group_command = common_command + [
            "--json-schema", json.dumps(GROUP_SCHEMA, separators=(",", ":")),
        ]
        aggregate_command = common_command + [
            "--json-schema", json.dumps(AGGREGATE_SCHEMA, separators=(",", ":")),
        ]
        env = {
            "HOME": "/nonexistent", "PATH": safe_path, "LANG": "C.UTF-8",
            "ANTHROPIC_API_KEY": token, "ANTHROPIC_AUTH_TOKEN": token,
            "ANTHROPIC_BASE_URL": ENDPOINT, "CLAUDE_CODE_SIMPLE": "1",
            **reviewer_transport_environment(),
        }
        results = []
        groups = aggregate_groups(diff, plan)
        group_manifest_hash = aggregate_group_manifest_hash(
            base, head, diff_hash, manifest_hash, groups,
        )

        def fail(stage, chunk_index, command, started_at, terminal_status, exit_code,
                 stdout="", stderr="", details=None, group_index=None,
                 group_output_attempts=()):
            _raise_attempt_failure(
                evidence_fd=evidence_fd, evidence_dir=evidence, run_id=run_id,
                repository=repository, mission_id=args.mission_id, base=base, head=head,
                diff_hash=diff_hash, stage=stage, chunk_index=chunk_index,
                started_at=started_at, completed_at=time.time(),
                terminal_status=terminal_status, exit_code=exit_code, command=command,
                stdout=stdout, stderr=stderr, token=token, details=details,
                completed_chunks=plan, group_index=group_index,
                completed_groups=groups,
                group_output_attempts=group_output_attempts,
            )

        for chunk in plan:
            source = diff[chunk["start"]:chunk["end"]]
            call_started_at = time.time()
            try:
                completed = invoke_reviewer(
                    chunk_command,
                    prompt(base, head, diff_hash, manifest_hash, chunk, source),
                    env, args.timeout,
                )
            except subprocess.TimeoutExpired as exc:
                fail(
                    "chunk", chunk["index"], chunk_command, call_started_at,
                    "TIMED_OUT", None, exc.stdout, exc.stderr,
                    ReviewFailureDetails(
                        ReviewFailureClassification.TRANSIENT_TRANSPORT,
                        "reviewer_request_timeout",
                        "reviewer subprocess exceeded the configured request timeout",
                    ),
                )
            except OSError:
                fail(
                    "chunk", chunk["index"], chunk_command, call_started_at,
                    "NOT_STARTED", None, details=ReviewFailureDetails(
                        ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                        "reviewer_process_start_failed",
                        "trusted reviewer process could not be started",
                    ),
                )
            if _credential_echoed(completed.stdout, completed.stderr, token):
                fail("chunk", chunk["index"], chunk_command, call_started_at,
                     "OUTPUT_REJECTED", completed.returncode,
                     completed.stdout, completed.stderr)
            if completed.returncode:
                fail("chunk", chunk["index"], chunk_command, call_started_at,
                     "EXITED", completed.returncode,
                     completed.stdout, completed.stderr)
            try:
                result = reviewer_result(completed.stdout, forbid_dispositions=True)
            except (ValueError, TypeError) as exc:
                fail("chunk", chunk["index"], chunk_command, call_started_at,
                     "OUTPUT_REJECTED", completed.returncode,
                     completed.stdout, completed.stderr, _output_failure_details(exc))
            raw = _captured_bytes(completed.stdout)
            write_private_artifact(evidence_fd, f"chunk-{chunk['index']:03d}.json", raw, run_id)
            chunk["result"] = result
            chunk["output_sha256"] = digest(raw)
            results.extend(result.get("findings", []))

        for group in groups:
            group_chunks=[chunk for chunk in plan if chunk["index"] in group["chunk_indexes"]]
            group_findings, group_required = indexed_chunk_findings(group_chunks)
            group_text=aggregate_group_prompt(
                base,head,diff_hash,manifest_hash,group_manifest_hash,group,
                plan,diff[group["start"]:group["end"]],group_findings,group_required,
            )
            try:
                bounded_prompt_bytes(group_text)
            except ValueError as exc:
                fail("aggregate_group",None,group_command,time.time(),"NOT_STARTED",None,
                     details=ReviewFailureDetails(
                         ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                         "bounded_group_prompt_rejected",
                         "aggregate group request exceeded the safe prompt size limit",
                     ),group_index=group["index"])
            group_output_attempts = []
            format_retry_count = 0
            while True:
                call_started_at=time.time()
                try:
                    group_call=invoke_reviewer(group_command,group_text,env,args.timeout)
                except subprocess.TimeoutExpired as exc:
                    fail("aggregate_group",None,group_command,call_started_at,
                         "TIMED_OUT",None,exc.stdout,exc.stderr,
                         ReviewFailureDetails(
                             ReviewFailureClassification.TRANSIENT_TRANSPORT,
                             "reviewer_request_timeout",
                             "reviewer subprocess exceeded the configured request timeout",
                         ),group_index=group["index"],
                         group_output_attempts=group_output_attempts)
                except OSError:
                    fail("aggregate_group",None,group_command,call_started_at,
                         "NOT_STARTED",None,details=ReviewFailureDetails(
                             ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                             "reviewer_process_start_failed",
                             "trusted reviewer process could not be started",
                         ),group_index=group["index"],
                         group_output_attempts=group_output_attempts)
                if _credential_echoed(group_call.stdout,group_call.stderr,token):
                    fail("aggregate_group",None,group_command,call_started_at,
                         "OUTPUT_REJECTED",group_call.returncode,group_call.stdout,
                         group_call.stderr,group_index=group["index"],
                         group_output_attempts=group_output_attempts)
                if group_call.returncode:
                    fail("aggregate_group",None,group_command,call_started_at,
                         "EXITED",group_call.returncode,group_call.stdout,group_call.stderr,
                         group_index=group["index"],
                         group_output_attempts=group_output_attempts)

                diagnostic = reviewer_output_diagnostics(
                    group_call.stdout, require_dispositions=True,
                    allow_summary=True, require_summary=True,
                )
                if diagnostic["reason_code"] != "VALID":
                    initial_details = _group_output_failure_details(diagnostic)
                    retry_scheduled = (
                        initial_details.classification
                        == ReviewFailureClassification.TRANSIENT_STRUCTURED_OUTPUT_FORMAT_FAILURE
                        and format_retry_count < GROUP_OUTPUT_FORMAT_RETRY_LIMIT
                    )
                    details = _group_output_failure_details(
                        diagnostic, retry_exhausted=not retry_scheduled,
                    )
                    attempt_name, attempt_sha256 = _publish_group_output_attempt(
                        evidence_fd=evidence_fd, run_id=run_id,
                        repository=repository, mission_id=args.mission_id,
                        base=base, head=head, diff_hash=diff_hash, group=group,
                        prompt_text=group_text, command=group_command,
                        diagnostic=diagnostic, attempt_index=format_retry_count,
                        retry_scheduled=retry_scheduled,
                        stdout=group_call.stdout, stderr=group_call.stderr,
                        details=initial_details if retry_scheduled else details,
                    )
                    group_output_attempts.append({
                        "group_index": group["index"],
                        "attempt_index": format_retry_count,
                        "path": attempt_name,
                        "sha256": attempt_sha256,
                        "reason_code": diagnostic["reason_code"],
                    })
                    if retry_scheduled:
                        format_retry_count += 1
                        continue
                    fail("aggregate_group",None,group_command,call_started_at,
                         "OUTPUT_REJECTED",group_call.returncode,group_call.stdout,
                         group_call.stderr,details,group_index=group["index"],
                         group_output_attempts=group_output_attempts)

                try:
                    group_result=reviewer_group_result(group_call.stdout)
                    validate_blocker_dispositions(group_chunks,group_result)
                except (ValueError,TypeError) as exc:
                    details = _output_failure_details(exc)
                    attempt_name, attempt_sha256 = _publish_group_output_attempt(
                        evidence_fd=evidence_fd, run_id=run_id,
                        repository=repository, mission_id=args.mission_id,
                        base=base, head=head, diff_hash=diff_hash, group=group,
                        prompt_text=group_text, command=group_command,
                        diagnostic=diagnostic, attempt_index=format_retry_count,
                        retry_scheduled=False, stdout=group_call.stdout,
                        stderr=group_call.stderr, details=details,
                    )
                    group_output_attempts.append({
                        "group_index": group["index"],
                        "attempt_index": format_retry_count,
                        "path": attempt_name,
                        "sha256": attempt_sha256,
                        "reason_code": details.reason_code,
                    })
                    fail("aggregate_group",None,group_command,call_started_at,
                         "OUTPUT_REJECTED",group_call.returncode,group_call.stdout,
                         group_call.stderr,details,group_index=group["index"],
                         group_output_attempts=group_output_attempts)
                break
            group_raw=_captured_bytes(group_call.stdout)
            write_private_artifact(evidence_fd,f"group-{group['index']:03d}.json",group_raw,run_id)
            group["result"]=group_result
            group["output_sha256"]=digest(group_raw)

        group_findings, required_dispositions = indexed_chunk_findings(
            groups, source_index_field="group_index",
        )
        aggregate_text=aggregate_prompt(
            base,head,diff_hash,manifest_hash,group_manifest_hash,groups,
            group_findings,required_dispositions,
        )
        try:
            bounded_prompt_bytes(aggregate_text)
        except ValueError:
            fail("aggregate",None,aggregate_command,time.time(),"NOT_STARTED",None,
                 details=ReviewFailureDetails(
                     ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                     "bounded_aggregate_prompt_rejected",
                     "final aggregate request exceeded the safe prompt size limit",
                 ))
        call_started_at=time.time()
        try:
            aggregate_call=invoke_reviewer(aggregate_command,aggregate_text,env,args.timeout)
        except subprocess.TimeoutExpired as exc:
            fail("aggregate",None,aggregate_command,call_started_at,
                 "TIMED_OUT",None,exc.stdout,exc.stderr,
                 ReviewFailureDetails(
                     ReviewFailureClassification.TRANSIENT_TRANSPORT,
                     "reviewer_request_timeout",
                     "reviewer subprocess exceeded the configured request timeout",
                 ))
        except OSError:
            fail("aggregate",None,aggregate_command,call_started_at,
                 "NOT_STARTED",None,details=ReviewFailureDetails(
                     ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                     "reviewer_process_start_failed",
                     "trusted reviewer process could not be started",
                 ))
        if _credential_echoed(aggregate_call.stdout,aggregate_call.stderr,token):
            fail("aggregate",None,aggregate_command,call_started_at,
                 "OUTPUT_REJECTED",aggregate_call.returncode,
                 aggregate_call.stdout,aggregate_call.stderr)
        if aggregate_call.returncode:
            fail("aggregate",None,aggregate_command,call_started_at,
                 "EXITED",aggregate_call.returncode,
                 aggregate_call.stdout,aggregate_call.stderr)
        try:
            aggregate_result=reviewer_result(
                aggregate_call.stdout,require_dispositions=True,
                disposition_index_field="group_index",
            )
            validate_blocker_dispositions(
                [{"index":group["index"],"result":group["result"]} for group in groups],
                aggregate_result,allow_disputes=False,source_index_field="group_index",
            )
        except (ValueError,TypeError) as exc:
            fail("aggregate",None,aggregate_command,call_started_at,
                 "OUTPUT_REJECTED",aggregate_call.returncode,
                 aggregate_call.stdout,aggregate_call.stderr,_output_failure_details(exc))

        aggregate_raw = _captured_bytes(aggregate_call.stdout)
        write_private_artifact(evidence_fd, "aggregate.json", aggregate_raw, run_id)
        verdict = aggregate_result["review_result"]
        receipt = {
            "version": VERSION, "repository": repository, "mission_id": args.mission_id,
            "base_sha": base, "head_sha": head, "diff_sha256": diff_hash,
            "manifest_sha256": manifest_hash,
            "group_manifest_sha256": group_manifest_hash,
            "chunks": plan, "groups": groups,
            "chunk_findings": results, "aggregate_result": aggregate_result,
            "aggregate_output_sha256": digest(aggregate_raw), "provider": "deepseek",
            "model": MODEL,
            "command_sha256": digest(canon({"chunk": chunk_command,
                                             "group": group_command,
                                             "aggregate": aggregate_command})),
            "started_at": int(run_started_at), "completed_at": int(time.time()),
            "review_result": verdict, "findings": aggregate_result["findings"],
        }
        receipt["integrity_sha256"] = digest(canon(receipt))
        receipt["auth_hmac_sha256"] = auth_digest(receipt, token)
        path = evidence / f"deepseek-receipt-{head[:12]}-{run_id}.json"
        validate(receipt, base, head, root, path, args.mission_id, repository, secret=token)
        write_private_artifact(evidence_fd, path.name, canon(receipt), run_id)
        persisted = json.loads(read_private_artifact(evidence_fd, path.name))
        validate(persisted, base, head, root, path, args.mission_id, repository, secret=token)
        os.fsync(evidence_fd)
        print(json.dumps({"status": verdict, "receipt": str(path),
                          "review_receipt": str(path), "head_sha": head}))
    finally:
        if settings is not None:
            Path(settings.name).unlink(missing_ok=True)
        env.clear()
        token = ""
        if evidence_fd is not None:
            os.close(evidence_fd)
        if evidence_root_fd is not None:
            os.close(evidence_root_fd)
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    r=sub.add_parser("run"); r.add_argument("--repo",default="."); r.add_argument("--mission-id",default="codex-mission-harness"); r.add_argument("--base",required=True); r.add_argument("--head",required=True); r.add_argument("--evidence",required=True); r.add_argument("--token-file",required=True); r.add_argument("--timeout",type=int,default=900)
    c=sub.add_parser("validate"); c.add_argument("--receipt",required=True); c.add_argument("--base",required=True); c.add_argument("--head",required=True); c.add_argument("--repo",default="."); c.add_argument("--mission-id",default="codex-mission-harness"); c.add_argument("--token-file",required=True)
    a=p.parse_args()
    try:
        if a.cmd=="run": run(a)
        else:
            root=Path(a.repo).resolve(); receipt_path=Path(a.receipt)
            _,evidence_fd=open_private_directory(receipt_path.parent,root)
            token=""
            try:
                receipt=json.loads(read_private_artifact(evidence_fd,receipt_path.name))
                repository=repository_identity(git(root,"config","--get","remote.origin.url").decode().strip())
                token=read_token_file(a.token_file,root)
                print(json.dumps({"status":validate(receipt,full_sha(a.base),full_sha(a.head),root,receipt_path,a.mission_id,repository,secret=token)["review_result"]}))
            finally:
                token=""; os.close(evidence_fd)
    except ReviewAttemptFailure as exc:
        print(json.dumps(exc.as_payload(), sort_keys=True, separators=(",", ":")))
        return 1
    except Exception:
        # Unexpected local errors must fail closed without reflecting command,
        # environment, credential-file, or provider data into the log.
        print(json.dumps({
            "status": "BLOCKED_EXTERNAL",
            "failure_classification": ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE.value,
            "retryable": False,
            "error": "DeepSeek review failed before a valid receipt was produced",
        }, sort_keys=True, separators=(",", ":")))
        return 1
    return 0
if __name__=="__main__": raise SystemExit(main())

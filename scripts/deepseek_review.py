#!/usr/bin/env python3
"""Durable, exact-diff DeepSeek review for this repository only.

The caller supplies a token-file path at execution time; no credential is ever
stored in the mission, journal, receipt, or repository.  Receipt publication is
commit-last: an incomplete run has no receipt and is never an approval.
"""
from __future__ import annotations

import argparse, base64, hashlib, hmac, json, os, pwd, re, shutil, stat, subprocess, sys, tempfile, time, uuid
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "cmh-deepseek-review/v4"
MODEL = "deepseek-flash"
ENDPOINT = "https://api.deepseek.com/anthropic"
CHUNK_BYTES = 32000
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
    "properties": {**_REVIEW_PROPERTIES, "dispositions": _DISPOSITION_SCHEMA},
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
            and value.get("severity") in {"P0","P1","P2","P3"}
            and isinstance(value.get("title"),str) and bool(value["title"])
            and isinstance(value.get("evidence"),str) and bool(value["evidence"]))
def reviewer_result(raw, *, require_dispositions=False, forbid_dispositions=False):
    value = json.loads(raw)
    result = value.get("structured_output") or value.get("result") or value
    required = {"review_result", "findings"}
    allowed = required | {"dispositions"}
    if (not isinstance(result, dict) or not required <= set(result)
            or set(result) - allowed or result.get("review_result") not in {"PASS", "FAIL"}
            or not isinstance(result.get("findings"), list)
            or not all(finding(item) for item in result["findings"])):
        raise ValueError("invalid reviewer output")
    if forbid_dispositions and "dispositions" in result:
        raise ValueError("chunk reviewer output cannot contain aggregate dispositions")
    if require_dispositions and not isinstance(result.get("dispositions"), list):
        raise ValueError("aggregate reviewer omitted blocker dispositions")
    if "dispositions" in result:
        if not isinstance(result["dispositions"], list):
            raise ValueError("invalid reviewer dispositions")
        fields = {"chunk_index", "finding_index", "source_severity", "finding_sha256",
                  "decision", "rationale"}
        for item in result["dispositions"]:
            if (not isinstance(item, dict) or set(item) != fields
                    or type(item.get("chunk_index")) is not int or item["chunk_index"] < 0
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


def validate_blocker_dispositions(chunks_, aggregate_result):
    """Require an auditable aggregate decision for every blocking chunk finding."""
    expected = {}
    for chunk in chunks_:
        chunk_index = chunk["index"]
        for finding_index, item in enumerate(chunk["result"]["findings"]):
            if item["severity"] in {"P0", "P1", "P2"}:
                expected[(chunk_index, finding_index)] = item

    observed = {}
    for item in aggregate_result.get("dispositions", []):
        identity = (item["chunk_index"], item["finding_index"])
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
        observed[identity] = item
    if set(observed) != set(expected):
        raise ValueError("aggregate omitted a blocking chunk finding disposition")


def indexed_chunk_findings(chunks_):
    """Build the aggregate's indexed findings and precomputed blocker hashes."""
    all_findings = []
    required_dispositions = []
    for chunk in chunks_:
        for finding_index, item in enumerate(chunk["result"]["findings"]):
            all_findings.append({
                "chunk_index": chunk["index"],
                "finding_index": finding_index,
                "finding": item,
            })
            if item["severity"] in {"P0", "P1", "P2"}:
                required_dispositions.append({
                    "chunk_index": chunk["index"],
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
def validate(receipt, base, head, root=None, receipt_path=None, mission_id=None, repository=None, secret=None):
    required={"version","repository","mission_id","base_sha","head_sha","diff_sha256","manifest_sha256","chunks","chunk_findings","aggregate_result","aggregate_output_sha256","provider","model","command_sha256","review_result","findings","integrity_sha256","auth_hmac_sha256"}
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
    aggregate_result = reviewer_result(
        json.dumps(receipt["aggregate_result"]), require_dispositions=True
    )
    if not isinstance(receipt["aggregate_output_sha256"], str) or len(receipt["aggregate_output_sha256"]) != 64:
        raise ValueError("aggregate output identity is incomplete")
    if receipt["review_result"] != aggregate_result["review_result"]:
        raise ValueError("aggregate verdict mismatch")
    # Every blocking chunk finding remains in the receipt and must be explicitly
    # upheld or disputed by the complete-diff aggregate. The decision is bound
    # to the exact chunk finding and its rationale is part of the signed receipt.
    validate_blocker_dispositions(chunks_, aggregate_result)
    if aggregate_result["findings"] != receipt["findings"]:
        raise ValueError("aggregate findings mismatch")
    if root is not None:
        diff=git(Path(root).resolve(),"diff","--no-ext-diff","--no-textconv","--binary",f"{base}..{head}")
        if position!=len(diff) or digest(diff)!=receipt["diff_sha256"]: raise ValueError("receipt diff coverage mismatch")
        if descriptors!=chunks(diff): raise ValueError("chunk manifest does not match exact diff")
        manifest={"version":"cmh-deepseek-chunks/v2","base_sha":base,"head_sha":head,"diff_sha256":digest(diff),"chunks":descriptors}
        if digest(canon(manifest))!=receipt["manifest_sha256"]: raise ValueError("chunk manifest hash mismatch")
        if receipt_path is not None:
            evidence=Path(os.path.abspath(receipt_path)).parent
            evidence_fd=None
            try:
                _, evidence_fd=open_private_directory(evidence, root)
                for chunk in chunks_:
                    artifact=read_private_artifact(evidence_fd,f"chunk-{chunk['index']:03d}.json")
                    if digest(artifact)!=chunk["output_sha256"]: raise ValueError("chunk artifact mismatch")
                    if reviewer_result(artifact.decode("utf-8"), forbid_dispositions=True)!=chunk["result"]: raise ValueError("chunk result does not match durable artifact")
                aggregate_artifact=read_private_artifact(evidence_fd,"aggregate.json")
                if digest(aggregate_artifact) != receipt["aggregate_output_sha256"]:
                    raise ValueError("aggregate artifact mismatch")
                if reviewer_result(aggregate_artifact.decode("utf-8"), require_dispositions=True) != aggregate_result:
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

def aggregate_prompt(base, head, diff_hash, manifest_hash, plan, source, chunk_findings,
                     required_dispositions):
    """Ask the independent reviewer to inspect the complete diff once.

    Chunk reviews provide durable localized evidence.  This final pass prevents
    a cross-chunk defect from disappearing merely because each slice looked
    locally plausible; it receives the same exact bytes and hashes.
    """
    try: rendered = "UTF-8 COMPLETE DIFF:\n" + source.decode("utf-8")
    except UnicodeDecodeError: rendered = "BASE64-ENCODED EXACT COMPLETE DIFF BYTES:\n" + base64.b64encode(source).decode("ascii")
    return ("You are the final independent reviewer for the complete exact diff. Do not use tools or filesystem. "
            "Return only JSON matching the schema. PASS only when P0/P1/P2 are absent. "
            "Review cross-file and cross-chunk interactions, state transitions, and security boundaries. "
            "Account for every P0/P1/P2 chunk finding in dispositions. Copy each chunk_index, finding_index, source_severity, and finding_sha256 exactly from RequiredDispositions; do not calculate, modify, omit, or duplicate these values. Use UPHELD when the finding is valid and include the exact finding object in findings; use DISPUTED only when the complete diff disproves it, with a specific rationale grounded in the diff. A disputed finding stays in the durable receipt with its rationale. PASS is allowed only when findings contain no P0/P1/P2.\n"
            f"Base={base}\nHead={head}\nDiffSHA256={diff_hash}\nManifestSHA256={manifest_hash}\n"
            f"ChunkCount={len(plan)}\nChunkFindings={json.dumps(chunk_findings, sort_keys=True)}\n"
            f"RequiredDispositions={json.dumps(required_dispositions, sort_keys=True)}\n" + rendered)

def invoke_reviewer(command, prompt_text, env, timeout):
    # Keep the exact diff in the reviewer's input, but do not put the complete
    # synthesis prompt in argv.  Large release diffs can exceed ARG_MAX (the
    # chunk prompts happen to fit while the full-diff prompt does not).  Claude
    # Code's print mode explicitly supports text prompts on stdin, which also
    # avoids exposing source bytes through process listings.
    return subprocess.run(command, input=prompt_text, env=env, capture_output=True,
                          text=True, timeout=timeout)

def reject_credential_echo(completed, token):
    """Reject secrets on either captured stream without reflecting the stream."""
    secret = token.encode("utf-8")
    for output in (completed.stdout, completed.stderr):
        if isinstance(output, str) and secret in output.encode("utf-8"):
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
    root=Path(args.repo).resolve(); base=full_sha(args.base); head=full_sha(args.head)
    if git(root,"rev-parse","HEAD").decode().strip().lower()!=head: raise ValueError("worktree HEAD differs from requested HEAD")
    repository=repository_identity(git(root,"config","--get","remote.origin.url").decode().strip())
    diff=git(root,"diff","--no-ext-diff","--no-textconv","--binary",f"{base}..{head}"); plan=chunks(diff); diff_hash=digest(diff)
    claude_executable,safe_path=resolve_claude_launcher(root,os.environ.get("PATH",""))
    manifest={"version":"cmh-deepseek-chunks/v2","base_sha":base,"head_sha":head,"diff_sha256":diff_hash,"chunks":[dict(chunk) for chunk in plan]}; manifest_hash=digest(canon(manifest))
    token=read_token_file(args.token_file,root)
    if not token: raise ValueError("empty DeepSeek token file")
    evidence_root_fd=None; evidence_fd=None; settings=None; env={}
    try:
        evidence_root,evidence_root_fd=open_private_directory(args.evidence,root)
        run_id=uuid.uuid4().hex; evidence=evidence_root/run_id
        evidence_fd=create_private_child_directory(evidence_root_fd,run_id)
        settings=tempfile.NamedTemporaryFile(mode="w",delete=False)
        settings.write('{"permissions":{"allow":[],"deny":["Bash","Edit","Write","Read","Glob","Grep","WebFetch","WebSearch"]}}')
        settings.close()
        common_command=[claude_executable,"--bare","--restricted","--print","--model",MODEL,"--settings",settings.name,"--tools","","--disallowed-tools","Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch","--output-format","json"]
        chunk_command=common_command+["--json-schema",json.dumps(CHUNK_SCHEMA,separators=(",",":"))]
        aggregate_command=common_command+["--json-schema",json.dumps(AGGREGATE_SCHEMA,separators=(",",":"))]
        env={"HOME":"/nonexistent","PATH":safe_path,"LANG":"C.UTF-8","ANTHROPIC_API_KEY":token,"ANTHROPIC_AUTH_TOKEN":token,"ANTHROPIC_BASE_URL":ENDPOINT,"CLAUDE_CODE_SIMPLE":"1", **reviewer_transport_environment()}
        results=[]
        for chunk in plan:
            source=diff[chunk["start"]:chunk["end"]]
            completed=invoke_reviewer(chunk_command,prompt(base,head,diff_hash,manifest_hash,chunk,source),env,args.timeout)
            reject_credential_echo(completed, token)
            if completed.returncode: raise RuntimeError(f"DeepSeek reviewer infrastructure failure: exit={completed.returncode}")
            raw=completed.stdout.encode()
            write_private_artifact(evidence_fd,f"chunk-{chunk['index']:03d}.json",raw,run_id)
            result=reviewer_result(completed.stdout, forbid_dispositions=True)
            chunk["result"]=result; chunk["output_sha256"]=digest(raw); results.extend(result.get("findings",[]))
        chunk_findings, required_dispositions = indexed_chunk_findings(plan)
        aggregate_call=invoke_reviewer(
            aggregate_command,
            aggregate_prompt(base, head, diff_hash, manifest_hash, plan, diff,
                             chunk_findings, required_dispositions),
            env, args.timeout,
        )
        reject_credential_echo(aggregate_call, token)
        if aggregate_call.returncode:
            raise RuntimeError(f"DeepSeek aggregate reviewer infrastructure failure: exit={aggregate_call.returncode}")
        aggregate_raw=aggregate_call.stdout.encode()
        write_private_artifact(evidence_fd,"aggregate.json",aggregate_raw,run_id)
        aggregate_result=reviewer_result(aggregate_call.stdout, require_dispositions=True)
        validate_blocker_dispositions(plan, aggregate_result)
        verdict=aggregate_result["review_result"]
        receipt={"version":VERSION,"repository":repository,"mission_id":args.mission_id,"base_sha":base,"head_sha":head,"diff_sha256":diff_hash,"manifest_sha256":manifest_hash,"chunks":plan,"chunk_findings":results,"aggregate_result":aggregate_result,"aggregate_output_sha256":digest(aggregate_raw),"provider":"deepseek","model":MODEL,"command_sha256":digest(canon({"chunk":chunk_command,"aggregate":aggregate_command})),"started_at":int(time.time()),"completed_at":int(time.time()),"review_result":verdict,"findings":aggregate_result["findings"]}
        receipt["integrity_sha256"]=digest(canon(receipt)); receipt["auth_hmac_sha256"]=auth_digest(receipt,token)
        path=evidence/f"deepseek-receipt-{head[:12]}-{run_id}.json"
        validate(receipt,base,head,root,path,args.mission_id,repository,secret=token)
        write_private_artifact(evidence_fd,path.name,canon(receipt),run_id)
        persisted=json.loads(read_private_artifact(evidence_fd,path.name))
        validate(persisted,base,head,root,path,args.mission_id,repository,secret=token)
        os.fsync(evidence_fd)
        print(json.dumps({"status":verdict,"receipt":str(path),"review_receipt":str(path),"head_sha":head}))
    finally:
        if settings is not None:
            Path(settings.name).unlink(missing_ok=True)
        env.clear(); token=""
        if evidence_fd is not None: os.close(evidence_fd)
        if evidence_root_fd is not None: os.close(evidence_root_fd)
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
    except Exception as exc: print(json.dumps({"status":"BLOCKED_EXTERNAL","error":str(exc)})); return 1
    return 0
if __name__=="__main__": raise SystemExit(main())

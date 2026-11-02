"""Pinned, read-only contract source for offline tests; never a live project gate."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

CONTRACT_HEAD = "a65464d1e5de498a072ed9a8fdf69ce46bcc04c5"
CONTRACT_TREE = "e8b62991f586b8e1127653db36e5437f262007c1"


class ContractUnavailable(RuntimeError):
    """A mandatory test dependency is missing, stale or incomplete; never PASS/skip."""


def read_git(source, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0")
    result = subprocess.run(["git", "--no-replace-objects", "--no-optional-locks", "-C", str(source),
                             "-c", "core.fsmonitor=false", *args], env=env,
                            capture_output=True, timeout=30)
    if result.returncode:
        # Do not echo arbitrary Git config/transport stderr or credentials.
        raise ContractUnavailable("BLOCKED_CONTRACT_SOURCE: pinned local Git source is unavailable")
    return result.stdout


def require_source():
    source = Path(os.environ.get("FOOTBALLPREDICTION_CONTRACT_REPO",
        str(Path(__file__).resolve().parents[2] / "FootballPrediction"))).resolve()
    if not source.is_dir():
        raise ContractUnavailable("BLOCKED_CONTRACT_SOURCE: set FOOTBALLPREDICTION_CONTRACT_REPO to the complete pinned checkout")
    if (read_git(source, "rev-parse", "--show-toplevel").decode().strip() != str(source)
            or read_git(source, "rev-parse", "HEAD").decode().strip() != CONTRACT_HEAD
            or read_git(source, "rev-parse", CONTRACT_HEAD + "^{tree}").decode().strip() != CONTRACT_TREE):
        raise ContractUnavailable("BLOCKED_CONTRACT_SOURCE: exact contract HEAD/tree mismatch; latest HEAD cannot substitute")
    return source


def verify_source():
    """Check the entire Git tree and physical bytes/modes without running its code."""
    source = require_source()
    files = 0
    for item in read_git(source, "ls-tree", "-rz", CONTRACT_HEAD).split(b"\0"):
        if not item:
            continue
        metadata, raw_path = item.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        path = source / os.fsdecode(raw_path)
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ContractUnavailable("BLOCKED_CONTRACT_SOURCE: incomplete or unsupported contract entry")
        try:
            data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
            actual_mode = "120000" if path.is_symlink() else ("100755" if path.stat().st_mode & 0o111 else "100644")
        except OSError as exc:
            raise ContractUnavailable("BLOCKED_CONTRACT_SOURCE: tracked contract file unavailable") from exc
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual_blob != blob or actual_mode != mode:
            raise ContractUnavailable("BLOCKED_CONTRACT_SOURCE: tracked contract bytes/mode mismatch")
        files += 1
    if read_git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ContractUnavailable("BLOCKED_CONTRACT_SOURCE: contract checkout must be clean")
    return dict(status="CONTRACT_SOURCE_VERIFIED", source=str(source), head=CONTRACT_HEAD,
                tree=CONTRACT_TREE, tracked_files=files, live_project_validation=False)


def raise_prerequisite(result):
    """Only a typed missing prerequisite is classified here. It remains an error."""
    if "prerequisite_error" in result:
        value = result["prerequisite_error"]
        if ("driver_error" in result or not isinstance(value, dict)
                or value.get("code") != "BLOCKED_CONTRACT_SOURCE"
                or not isinstance(value.get("message"), str)):
            raise ValueError("invalid or conflicting subprocess prerequisite report")
        raise ContractUnavailable(value["message"])


if __name__ == "__main__":
    try:
        print(json.dumps(verify_source(), sort_keys=True))
    except (ContractUnavailable, OSError, subprocess.SubprocessError) as exc:
        print("BLOCKED_CONTRACT_SOURCE: mandatory contract verification failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)

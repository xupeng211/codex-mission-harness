"""One constructor-bound delegated session's private scratch, never a shared /tmp grant."""
from __future__ import annotations

import datetime
import ctypes
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import sys
import uuid


class TaskTempError(RuntimeError):
    def __init__(self, message, identity=None):
        super().__init__(message)
        self.identity = identity


def directory_identity(path, fd):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise TaskTempError("private directory allocation identity is unconfirmed: " + str(path))
    return {"path": str(path), "device": info.st_dev, "inode": info.st_ino,
            "uid": info.st_uid, "mode": "0o700"}


def allocate_directory(parent, prefix, binding):
    """Controller-only persistent validation scratch; not a delegated path input."""
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        identity = directory_identity(path, fd)
        identity.update(binding=binding, nonce=uuid.uuid4().hex)
        # Persisted nonce prevents inode recycling from adopting a later resource.
        marker = os.open(".cmh-allocation.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(marker, "w") as stream:
            json.dump({"nonce": identity["nonce"], "binding": binding}, stream, sort_keys=True)
            stream.flush(); os.fsync(stream.fileno())
        os.fsync(fd)
        return path, fd, identity
    except BaseException as error:
        if fd != -1:
            os.close(fd)
        raise TaskTempError("directory allocation unconfirmed; preserved at " + str(path), {"path": str(path)}) from error


def _validate_directory(fd, identity):
    actual = directory_identity(identity["path"], fd)
    if any(type(identity.get(k)) is not type(v) or identity[k] != v for k, v in actual.items()):
        raise TaskTempError("directory differs from original allocation", identity)
    if "nonce" in identity:
        marker = os.open(".cmh-allocation.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(marker, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise TaskTempError("directory allocation marker identity differs", identity)
            raw = stream.read(4097)
        if len(raw) > 4096 or json.loads(raw) != {"nonce": identity["nonce"], "binding": identity["binding"]}:
            raise TaskTempError("directory allocation nonce/binding differs", identity)


def _rename_noreplace(source_fd, source, destination_fd, destination):
    # No path-based or overwrite fallback on unsupported platforms/filesystems.
    if sys.platform != "linux":
        raise TaskTempError("identity-bound cleanup requires Linux renameat2")
    rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if rename is None:
        raise TaskTempError("identity-bound cleanup requires renameat2")
    if rename(source_fd, ctypes.c_char_p(os.fsencode(source)), destination_fd,
              ctypes.c_char_p(os.fsencode(destination)), 1) != 0:  # RENAME_NOREPLACE
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def remove_directory(path, identity, *, held_fd=None, claim_log=None):
    """Atomically claim a root, verify it, then delete in a private parent.

    The sandbox cannot access the fresh 0700 claim parent. Other Controller/host
    code must not mutate that parent or inject foreign resources into the owned
    tree. Public source-name replacement is allowed and never grants deletion.
    """
    path = Path(path)
    parent_fd = claim_fd = opened_fd = -1
    claim = None
    claimed = False
    try:
        if not shutil.rmtree.avoids_symlink_attacks or os.rename not in os.supports_dir_fd:
            raise TaskTempError("identity-bound directory cleanup is unsupported", identity)
        if str(path) != identity["path"] or not path.is_absolute() or path.resolve(strict=True) != path:
            raise TaskTempError("directory cleanup path binding differs", identity)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        _validate_directory(opened_fd, identity)
        if held_fd is not None:
            _validate_directory(held_fd, identity)
        claim = Path(tempfile.mkdtemp(prefix="cmh-cleanup-", dir=path.parent))
        claim_fd = os.open(claim, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        claim_identity = directory_identity(claim, claim_fd)
        if claim_log is not None:
            # Diagnostic recovery location is durable before the move. This is
            # a plan, never a cleanup receipt or authority to adopt a new path.
            log_fd = os.open(claim_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(log_fd, "w") as stream:
                stream.write(json.dumps({"identity": identity, "claim": claim_identity,
                    "phase": "prepared", "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}) + "\n")
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent_fd)
        # The atomic move captures any object substituted after validation.
        # No recursive deletion happens until that captured object matches.
        _rename_noreplace(parent_fd, path.name, claim_fd, "object")
        claimed = True
        captured = os.open("object", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=claim_fd)
        try:
            _validate_directory(captured, identity)
        finally:
            os.close(captured)
        shutil.rmtree("object", dir_fd=claim_fd)
        claimed = False
        # A recreated public name belongs to someone else. Preserve it, and do
        # not claim the operation's resource lifecycle is fully reconciled.
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TaskTempError("directory name was replaced during cleanup: " + str(path), identity)
    except Exception as error:
        retained = str(path)
        if claimed:
            try:
                _rename_noreplace(claim_fd, "object", parent_fd, path.name)
                claimed = False
            except Exception:
                retained = str(claim / "object")
        raise TaskTempError("directory cleanup unconfirmed; resource preserved at " + retained, identity) from error
    finally:
        try:
            if claim is not None and not claimed:
                # This fresh private parent is never delegated or reused.
                os.rmdir(claim.name, dir_fd=parent_fd)
        except OSError as error:
            raise TaskTempError("private cleanup parent unconfirmed: " + str(claim), identity) from error
        finally:
            for fd in (claim_fd, opened_fd, parent_fd):
                if fd != -1:
                    os.close(fd)


class TaskTemp:
    def __init__(self, worktree: str, profile: str, forbidden_roots=(), *, record: Path | None = None):
        # Do not inherit TMPDIR from a caller, profile, candidate or restored record.
        self.path = Path(tempfile.mkdtemp(prefix="cmh-delegated-", dir="/tmp"))
        self._fd = -1
        try:
            self._fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(self._fd)
        except OSError as exc:
            if self._fd != -1:
                os.close(self._fd)
            # Without a held identity, do not remove a possibly replaced path.
            # Factory records this exact identity in its UNKNOWN operation.
            raise TaskTempError("allocated task temporary workspace could not be bound; cleanup unconfirmed: " + str(self.path),
                                {"path": str(self.path), "worktree": worktree,
                                 "permission_profile": profile, "allocation_confirmed": False}) from exc
        self._identity = {"path": str(self.path), "worktree": worktree, "permission_profile": profile,
                          "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "mode": "0o700"}
        self._record = None
        self._closed = False
        try:
            self.validate(worktree, profile)
            for root in (Path(worktree), *map(Path, forbidden_roots)):
                if self.path.is_relative_to(root.resolve()):
                    raise TaskTempError("task temporary workspace overlaps a protected root")
            if record is not None:
                with record.open("x", encoding="utf-8") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    json.dump(self.identity, stream, sort_keys=True)
                    stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
                self._record = record
        except BaseException:
            self.close()
            raise

    @property
    def identity(self):
        return dict(self._identity)

    @property
    def cleanup_log(self):
        return self._record.with_suffix(".cleanup.jsonl") if self._record is not None else None

    def validate(self, worktree: str, profile: str):
        try:
            info = self.path.lstat()
            held = os.fstat(self._fd)
            if (self._closed or self.path.resolve(strict=True) != self.path
                    or not stat.S_ISDIR(info.st_mode) or self.path.is_symlink()
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                    or (info.st_dev, info.st_ino) != (held.st_dev, held.st_ino)
                    or (info.st_dev, info.st_ino) != (self._identity["device"], self._identity["inode"])
                    or worktree != self._identity["worktree"] or profile != self._identity["permission_profile"]):
                raise ValueError("identity, owner, mode or binding mismatch")
        except (OSError, ValueError) as exc:
            raise TaskTempError("task temporary workspace identity is unconfirmed: " + str(self.path), self.identity) from exc

    def environment(self):
        self.validate(self._identity["worktree"], self._identity["permission_profile"])
        return {key: str(self.path) for key in ("TMPDIR", "TMP", "TEMP")}

    def permission_rules(self):
        self.environment()  # Validate before emitting a grant.
        return {str(self.path): "write"}

    def environment_overrides(self):
        return [item for k, v in self.environment().items()
                for item in ("-c", "shell_environment_policy.set." + k + "=" + json.dumps(v))]

    def _cleanup_event(self, confirmed, error=None):
        result = {"identity": self.identity, "cleanup_confirmed": confirmed,
                  "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        if error is not None:
            result["error"] = str(error)
        if hasattr(self, "_process_stop"):
            result["process_stop"] = self._process_stop
        if self._record is not None:
            with self.cleanup_log.open("a", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(result, sort_keys=True) + "\n")
                stream.flush(); os.fsync(stream.fileno())
        return result

    def close(self):
        if self._closed:
            if not self._cleanup["cleanup_confirmed"]:
                raise TaskTempError("task temporary cleanup evidence is unconfirmed: " + str(self.path), self.identity)
            return self._cleanup
        try:
            self.validate(self._identity["worktree"], self._identity["permission_profile"])
            remove_directory(self.path, self.identity, held_fd=self._fd,
                             claim_log=self._record.with_suffix(".claims.jsonl") if self._record is not None else None)
            os.close(self._fd)
            self._fd = -1
            self._closed = True
            self._cleanup = {"identity": self.identity, "cleanup_confirmed": False}
            self._cleanup = self._cleanup_event(True)
            return self._cleanup
        except Exception as exc:
            try:
                self._cleanup_event(False, exc)
            except Exception as evidence_error:
                raise TaskTempError("task temporary cleanup/evidence unconfirmed: " + str(self.path), self.identity) from evidence_error
            raise TaskTempError("task temporary workspace cleanup unconfirmed: " + str(self.path), self.identity) from exc

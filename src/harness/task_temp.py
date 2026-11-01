"""One constructor-bound delegated session's private scratch, never a shared /tmp grant."""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile


class TaskTempError(RuntimeError):
    def __init__(self, message, identity=None):
        super().__init__(message)
        self.identity = identity


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
            if not shutil.rmtree.avoids_symlink_attacks:
                raise TaskTempError("safe task temporary cleanup is unsupported")
            # rmtree's fd-based traversal does not follow candidate-created links.
            # Keep the root fd open until deletion so inode reuse cannot pass validation.
            shutil.rmtree(self.path)
            if self.path.exists() or self.path.is_symlink():
                raise TaskTempError("task temporary workspace removal is unconfirmed")
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

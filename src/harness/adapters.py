"""Thin, fail-closed bridge to FootballPrediction's existing authorities."""
from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .review_failures import ReviewFailureClassification, classify_process_failure


@dataclass(frozen=True)
class GateResult:
    status: str  # PASS, FAIL, PENDING, BLOCKED_EXTERNAL
    evidence: str = ""
    artifact: str | None = None
    data: dict[str, Any] | None = None
    failure_classification: "ReviewFailureClassification | None" = None


class FootballPredictionAdapter:
    """Call project commands/GitHub; never duplicate their safety policy."""
    GATES = {"verify-targeted": ["make", "verify-targeted"], "verify-pr": ["make", "verify-pr"],
             "verify-strict": ["make", "verify-strict"], "agent-preflight": ["make", "agent-preflight"]}
    REVIEW_CONTRACT_PATHS = (
        "Makefile", "scripts/devops/codex_independent_review.py",
        "scripts/devops/codex_reviewer_isolation.py",
        "scripts/devops/codex_review_classification.py", "scripts/devops/codex_review_contract.py",
        "scripts/devops/codex_review_output.py", "scripts/devops/codex_review_provenance.py",
        "scripts/devops/codex_review_receipt.py", "scripts/devops/claude_deepseek_independent_review.py",
        "scripts/devops/deepseek_chunk_receipt_validation.py", "scripts/devops/deepseek_receipt_evidence.py",
        "scripts/devops/independent_review_protocol.py", "scripts/devops/independent_review_receipt.py",
        "scripts/devops/review_policy.py", "scripts/devops/agent_workflow.py",
        "scripts/devops/pr_post_merge_check.py", "scripts/devops/exact_head.py",
        "docs/agentic/independent_review_backends.json",
        "schemas/agentic/codex_review_result.schema.json", "schemas/agentic/codex_review_receipt.schema.json",
        "schemas/agentic/independent_review_result.schema.json", "schemas/agentic/independent_review_receipt.schema.json",
    )

    @staticmethod
    def _safe_mission_id(mission_id: str) -> str:
        if (not isinstance(mission_id, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", mission_id) is None
                or mission_id in {".", ".."}):
            raise ValueError("mission_id is not a safe evidence path component")
        return mission_id

    @classmethod
    def review_evidence_dir(cls, worktree: str, mission_id: str, reviewer: str, head: str) -> Path:
        mission_id = cls._safe_mission_id(mission_id)
        if reviewer not in {"codex", "deepseek"}:
            raise ValueError("unsupported independent reviewer")
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-fA-F]{40}", head) is None:
            raise ValueError("review HEAD must be a full commit SHA")
        repo = Path(worktree).resolve(strict=True)
        return repo.parent / ".cmh-review-evidence" / mission_id / reviewer / head.lower()

    def review_context_worktree(self, worktree: str, mission_id: str, head: str) -> Path:
        """Return a clean detached worktree materialized from the reviewed commit."""
        mission_id = self._safe_mission_id(mission_id)
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-fA-F]{40}", head) is None:
            raise ValueError("review context requires a full HEAD SHA")
        candidate = Path(worktree).resolve(strict=True)
        if not candidate.is_dir():
            raise RuntimeError("review context source is not a repository directory")
        head = head.lower()
        context = candidate.parent / f".cmh-review-context-{mission_id}-{head}"
        if context.is_symlink():
            raise RuntimeError("review context path is a symbolic link")

        git_env = {
            "PATH": self._trusted_system_path(),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
        # A writable candidate must not supply executable Git settings for a
        # controller operation (notably fsmonitor and checkout filters).
        self._assert_safe_local_git_config(str(candidate), git_env)
        if not context.exists():
            created = self._call(
                ["git", "-C", str(candidate), "-c", "core.hooksPath=/dev/null",
                 "-c", "core.attributesFile=/dev/null", "-c", "core.fsmonitor=false",
                 "--no-replace-objects", "worktree", "add", "--detach", str(context), head],
                cwd=str(candidate), env=git_env, inherit_environment=False,
            )
            if created.returncode != 0 and not context.exists():
                raise RuntimeError(created.stderr.strip() or "cannot materialize reviewed HEAD worktree")
        if context.is_symlink() or not context.is_dir():
            raise RuntimeError("review context path is not a real directory")
        info = context.lstat()
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise RuntimeError("review context is not owned by the current user")
        context.chmod(0o700)

        def git_text(root: Path, *args: str) -> str:
            return subprocess.check_output(
                ["git", "-c", "core.fsmonitor=false", "--no-replace-objects", "-C", str(root), *args],
                cwd=str(candidate), env=git_env, text=True, stderr=subprocess.PIPE,
                timeout=60,
            ).strip()

        if Path(git_text(context, "rev-parse", "--show-toplevel")).resolve() != context.resolve():
            raise RuntimeError("review context is not a registered repository worktree")
        if git_text(context, "rev-parse", "HEAD").lower() != head:
            raise RuntimeError("review context HEAD differs from the requested commit")
        if git_text(context, "status", "--porcelain=v1", "--untracked-files=all"):
            raise RuntimeError("review context contains uncommitted files")
        candidate_common = Path(git_text(candidate, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
        context_common = Path(git_text(context, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
        if candidate_common != context_common:
            raise RuntimeError("review context belongs to another repository")
        listing = git_text(candidate, "worktree", "list", "--porcelain")
        registered = any(
            block.splitlines()[0] == f"worktree {context}"
            and f"HEAD {head}" in block.splitlines()
            and "detached" in block.splitlines()
            for block in listing.split("\n\n") if block.strip()
        )
        if not registered:
            raise RuntimeError("review context is not registered as the exact detached worktree")
        return context

    def review_scope_file(self, worktree: str, head: str, relative_scope: str) -> Path:
        """Validate the review scope against the committed blob in a clean context."""
        if (not isinstance(relative_scope, str) or not relative_scope or "\\" in relative_scope
                or Path(relative_scope).is_absolute()
                or any(part in {"", ".", ".."} for part in relative_scope.split("/"))):
            raise ValueError("review scope path is not a safe repository-relative path")
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-fA-F]{40}", head) is None:
            raise ValueError("review scope requires a full HEAD SHA")
        root = Path(worktree).resolve(strict=True)
        scope = root.joinpath(*relative_scope.split("/"))
        if scope.is_symlink():
            raise RuntimeError("review scope in committed context is a symbolic link")
        git_env = {"PATH": self._trusted_system_path(), "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
        try:
            observed_head = subprocess.check_output(
                ["git", "--no-replace-objects", "-C", str(root), "rev-parse", "HEAD"],
                cwd=str(root), env=git_env, text=True, stderr=subprocess.PIPE, timeout=30,
            ).strip().lower()
            if observed_head != head.lower():
                raise RuntimeError("review context HEAD differs from the requested commit")
            committed = subprocess.check_output(
                ["git", "--no-replace-objects", "-C", str(root), "show",
                 f"{head}:{relative_scope}"],
                cwd=str(root), env=git_env,
                stderr=subprocess.PIPE, timeout=30,
            )
            observed = scope.read_bytes()
        except RuntimeError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("review scope is unavailable from the committed HEAD") from exc
        if not scope.is_file() or scope.is_symlink() or observed != committed:
            raise RuntimeError("review scope differs from the committed HEAD blob")
        return scope

    @staticmethod
    def _validate_review_evidence_dir(evidence_dir: Path) -> Path:
        evidence_dir = evidence_dir.absolute()
        for directory in (evidence_dir.parents[2], evidence_dir.parents[1],
                          evidence_dir.parents[0], evidence_dir):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or (hasattr(os, "getuid") and info.st_uid != os.getuid())
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise RuntimeError(f"review evidence directory is not private: {directory}")
        return evidence_dir.resolve(strict=True)

    def exact_head(self, worktree: str) -> str:
        dirty = self._run(["git", "-c", "core.fsmonitor=false", "-C", worktree,
                           "status", "--porcelain=v1", "--untracked-files=all"])
        if dirty:
            raise RuntimeError("canonical evidence requires a clean committed worktree")
        return self._run(["git", "-C", worktree, "rev-parse", "HEAD"]).strip().lower()

    def gate_argv(self, gate: str, **_context: Any) -> list[str]:
        if gate not in self.GATES: raise ValueError(f"unsupported canonical gate: {gate}")
        return self.GATES[gate]

    @staticmethod
    def _gh(*args: str) -> list[str]:
        return ["gh", *args]

    @staticmethod
    def _private_dir(path: Path, *, private_root: Path | None = None) -> Path:
        path = Path(os.path.abspath(path))
        private_root = Path(os.path.abspath(private_root or path))
        try:
            descendants = path.relative_to(private_root).parts
        except ValueError as exc:
            raise RuntimeError("evidence directory escapes its private root") from exc

        # The parent of the private root must be a stable anchor. Check every
        # existing ancestor without following symlinks and reject writable
        # non-sticky ancestors that could replace path entries.
        anchor = private_root.parent
        ancestors = [*reversed(anchor.parents), anchor]
        for directory in ancestors:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeError("evidence path has a non-directory or symbolic-link ancestor")
            if ((stat.S_IMODE(info.st_mode) & 0o022)
                    and not (stat.S_IMODE(info.st_mode) & stat.S_ISVTX)):
                raise RuntimeError("evidence path has an untrusted writable ancestor")
        anchor_info = anchor.lstat()
        anchor_mode = stat.S_IMODE(anchor_info.st_mode)
        sticky_shared_anchor = bool(
            (anchor_mode & stat.S_ISVTX) and (anchor_mode & 0o022)
        )
        if (hasattr(os, "getuid") and anchor_info.st_uid != os.getuid()
                and not sticky_shared_anchor):
            raise RuntimeError("evidence parent is not owned by the current user")
        if (anchor_mode & 0o022) and not (anchor_mode & stat.S_ISVTX):
            raise RuntimeError("evidence parent is writable by another user")

        directories = [private_root]
        current = private_root
        for part in descendants:
            current = current / part
            directories.append(current)
        for directory in directories:
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeError("evidence directory is not a real directory")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise RuntimeError("evidence directory is not owned by the current user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                directory.chmod(0o700)
                info = directory.lstat()
                if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or stat.S_IMODE(info.st_mode) & 0o077):
                    raise RuntimeError("evidence directory is not owner-only")
        return path

    @staticmethod
    def _write_private_file(path: Path, content: str, *, exclusive: bool = False) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise RuntimeError("safe no-follow evidence writes are unavailable")
        fd: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | nofollow
            if exclusive:
                flags |= os.O_EXCL
            fd = os.open(path, flags, 0o600)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
                raise RuntimeError("evidence file is not a single-link regular current-user-owned file")
            os.fchmod(fd, 0o600)
            if not exclusive:
                os.ftruncate(fd, 0)
            stream = os.fdopen(fd, "w", encoding="utf-8")
            fd = None
            with stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise RuntimeError("private evidence file could not be safely written") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def prepare_gate(self, gate: str, *, worktree: str, base: str, head: str,
                     mission_id: str, scope_file: str) -> GateResult:
        """Prepare explicit inputs required by FootballPrediction preflight."""
        if gate != "agent-preflight":
            return GateResult("PASS")
        pr = self.discover_pr(worktree, head)
        if pr.status != "PASS":
            return pr
        facts = pr.data if isinstance(pr.data, dict) else {}
        detail = self._pr_state(worktree, int(facts["number"]), str(facts["repo"]))
        if detail.status != "PASS":
            return detail
        current = detail.data if isinstance(detail.data, dict) else {}
        if (current.get("repo") != facts.get("repo")
                or current.get("head") != head.lower()
                or current.get("base") != facts.get("base")
                or current.get("base_sha") != facts.get("base_sha")
                or current.get("state") != "OPEN"):
            return GateResult("BLOCKED_EXTERNAL", "PR identity changed before preflight input preparation")
        body = (detail.data or {}).get("body") if isinstance(detail.data, dict) else None
        if not isinstance(body, str):
            return GateResult("BLOCKED_EXTERNAL", "PR discovery omitted a usable PR body")
        try:
            mission_id = self._safe_mission_id(mission_id)
        except ValueError as exc:
            return GateResult("BLOCKED_EXTERNAL", str(exc))
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-fA-F]{40}", head) is None:
            return GateResult("BLOCKED_EXTERNAL", "preflight HEAD is not a full commit SHA")
        worktree_root = Path(worktree).resolve(strict=True)
        evidence_root = worktree_root.parent / ".cmh-gate-evidence"
        try:
            evidence = self._private_dir(
                evidence_root / mission_id / head.lower(), private_root=evidence_root,
            )
            body_path = evidence / "pr-body.md"
            self._write_private_file(body_path, body)
        except (OSError, RuntimeError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot prepare private preflight evidence: {exc}")
        return GateResult("PASS", "canonical preflight inputs prepared", data={"env": {
            "PR_BODY": str(body_path), "MISSION_SCOPE_FILE": scope_file,
            "BASE_REF": base, "HEAD_REF": head, "JSON": "1",
        }})

    def review_preflight(self, worktree: str, base: str, head: str) -> GateResult:
        """Prove both immutable commits exist; policy executes from base checkout."""
        for revision in (base, head):
            try:
                self._trusted_git_output(Path(worktree), "cat-file", "-e", f"{revision}^{{commit}}")
            except (OSError, RuntimeError):
                return GateResult("BLOCKED_EXTERNAL", f"canonical review commit is unavailable: {revision}")
        return GateResult("PASS", "canonical policy will execute from trusted base")

    @classmethod
    def _trusted_git_environment(cls) -> dict[str, str]:
        """Use Git without ambient repository, config, or attribute overrides."""
        return {
            "PATH": cls._trusted_system_path(),
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

    def _trusted_git_output(self, root: Path, *args: str) -> str:
        result = self._call(
            ["git", "--no-replace-objects", "-C", str(root), *args],
            cwd=str(root), env=self._trusted_git_environment(), inherit_environment=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "trusted Git command failed")
        return result.stdout

    @classmethod
    def _trusted_python_interpreter(cls) -> str:
        """Return an absolute interpreter from the running process or system PATH."""
        candidates = [sys.executable]
        system_python = shutil.which("python3", path=cls._trusted_system_path())
        if system_python and system_python not in candidates:
            candidates.append(system_python)
        for candidate in candidates:
            executable = Path(candidate)
            if not executable.is_absolute():
                continue
            try:
                resolved = executable.resolve(strict=True)
                info = resolved.stat()
            except OSError:
                continue
            owners = {0, os.getuid()} if hasattr(os, "getuid") else {info.st_uid}
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners
                    or stat.S_IMODE(info.st_mode) & 0o022 or not os.access(resolved, os.X_OK)):
                continue
            trusted_path = True
            for directory in (resolved.parent, *resolved.parent.parents):
                try:
                    directory_info = directory.stat()
                except OSError:
                    trusted_path = False
                    break
                if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid not in owners
                        or stat.S_IMODE(directory_info.st_mode) & 0o022):
                    trusted_path = False
                    break
            if trusted_path:
                return str(resolved)
        raise RuntimeError("no trusted absolute Python interpreter is available")

    @staticmethod
    def _trusted_system_path() -> str:
        """Return only root-owned, non-writable system command directories."""
        safe: list[str] = []
        for entry in os.defpath.split(os.pathsep):
            if not entry or not Path(entry).is_absolute():
                continue
            try:
                directory = Path(entry).resolve(strict=True)
                info = directory.stat()
            except OSError:
                continue
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                continue
            trusted = True
            for ancestor in directory.parents:
                try:
                    ancestor_info = ancestor.stat()
                except OSError:
                    trusted = False
                    break
                if (not stat.S_ISDIR(ancestor_info.st_mode) or ancestor_info.st_uid != 0
                        or stat.S_IMODE(ancestor_info.st_mode) & 0o022):
                    trusted = False
                    break
            rendered = str(directory)
            if trusted and rendered not in safe:
                safe.append(rendered)
        if not safe:
            raise RuntimeError("trusted system command PATH is unavailable")
        return os.pathsep.join(safe)

    @staticmethod
    def _validate_executable(path: str, *, owners: set[int] | None = None) -> str:
        """Resolve one executable and verify its file and ancestor directories."""
        candidate = Path(path)
        if not candidate.is_absolute():
            raise RuntimeError("trusted executable path must be absolute")
        allowed_owners = owners or ({0, os.getuid()} if hasattr(os, "getuid") else {0})
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.stat()
        except OSError as exc:
            raise RuntimeError("trusted executable is unavailable") from exc
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in allowed_owners
                or stat.S_IMODE(info.st_mode) & 0o022 or not os.access(resolved, os.X_OK)):
            raise RuntimeError("trusted executable has unsafe ownership or permissions")
        for directory in (resolved.parent, *resolved.parent.parents):
            try:
                directory_info = directory.stat()
            except OSError as exc:
                raise RuntimeError("trusted executable has an unavailable parent directory") from exc
            if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid not in allowed_owners
                    or stat.S_IMODE(directory_info.st_mode) & 0o022):
                raise RuntimeError("trusted executable has an unsafe parent directory")
        return str(resolved)

    @classmethod
    def _trusted_system_executable(cls, name: str) -> str:
        """Resolve a bare command only from the verified system PATH."""
        if not isinstance(name, str) or not name or Path(name).name != name or name in {".", ".."}:
            raise RuntimeError("command name is not a safe basename")
        path = cls._trusted_system_path()
        candidate = shutil.which(name, path=path)
        if not candidate:
            raise RuntimeError(f"trusted system command is unavailable: {name}")
        return cls._validate_executable(candidate, owners={0})

    @classmethod
    def _trusted_command_argv(cls, argv):
        if not isinstance(argv, (list, tuple)) or not argv or not isinstance(argv[0], str):
            raise RuntimeError("trusted command arguments are malformed")
        command = argv[0]
        if Path(command).is_absolute():
            executable = cls._validate_executable(command)
        else:
            if "/" in command or "\\" in command:
                raise RuntimeError("relative executable paths are forbidden")
            executable = cls._trusted_system_executable(command)
        return [executable, *argv[1:]]

    @staticmethod
    def _trusted_search_path(path: str) -> str:
        """Validate an explicitly supplied search path used by trusted wrappers."""
        safe: list[str] = []
        owners = {0, os.getuid()} if hasattr(os, "getuid") else {0}
        for entry in path.split(os.pathsep):
            if not entry or not Path(entry).is_absolute():
                continue
            try:
                directory = Path(entry).resolve(strict=True)
                info = directory.stat()
            except OSError:
                continue
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                    or stat.S_IMODE(info.st_mode) & 0o022):
                continue
            trusted = True
            for ancestor in directory.parents:
                try:
                    ancestor_info = ancestor.stat()
                except OSError:
                    trusted = False
                    break
                if (not stat.S_ISDIR(ancestor_info.st_mode) or ancestor_info.st_uid not in owners
                        or stat.S_IMODE(ancestor_info.st_mode) & 0o022):
                    trusted = False
                    break
            rendered = str(directory)
            if trusted and rendered not in safe:
                safe.append(rendered)
        if not safe:
            raise RuntimeError("trusted subprocess PATH is unavailable")
        return os.pathsep.join(safe)

    @classmethod
    def _trusted_subprocess_environment(cls, *, env=None, inherit_environment=True) -> dict[str, str]:
        """Pass only deliberate process settings and required GitHub auth/network state."""
        child_env: dict[str, str] = {}
        if inherit_environment:
            try:
                home = Path(os.environ.get("HOME") or str(Path.home()))
                home_info = home.lstat()
                uid = os.getuid() if hasattr(os, "getuid") else home_info.st_uid
                if (home.is_absolute() and stat.S_ISDIR(home_info.st_mode)
                        and not stat.S_ISLNK(home_info.st_mode) and home_info.st_uid == uid
                        and not stat.S_IMODE(home_info.st_mode) & 0o022):
                    child_env["HOME"] = str(home.resolve(strict=True))
            except OSError:
                pass
            for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                         "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                         "http_proxy", "https_proxy", "all_proxy", "no_proxy",
                         "SSH_AUTH_SOCK", "SSH_AGENT_PID"):
                value = os.environ.get(name)
                if value:
                    child_env[name] = value
            for name in ("XDG_CONFIG_HOME", "GH_CONFIG_DIR"):
                value = os.environ.get(name, "")
                if not value or not Path(value).is_absolute():
                    continue
                try:
                    directory = Path(value)
                    info = directory.lstat()
                    home_path = Path(child_env.get("HOME", "/nonexistent"))
                    resolved = directory.resolve(strict=True)
                    uid = os.getuid() if hasattr(os, "getuid") else info.st_uid
                    if (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                            and info.st_uid == uid and not stat.S_IMODE(info.st_mode) & 0o022
                            and resolved.is_relative_to(home_path)):
                        child_env[name] = str(resolved)
                except (OSError, ValueError):
                    continue
            ca_names = (
                "CODEX_CA_CERTIFICATE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
                "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE",
            )
            for name in ca_names:
                value = os.environ.get(name, "")
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
                    child_env[name] = value

        overrides = dict(env or {})
        requested_path = overrides.pop("PATH", None)
        child_env.update(overrides)
        if inherit_environment:
            # A caller-provided PATH must not undo the safe default.
            child_env["PATH"] = cls._trusted_system_path()
        else:
            child_env["PATH"] = cls._trusted_search_path(requested_path or os.defpath)
        # Do not let user environment or call-site overrides select Git config
        # through variables that can redirect repositories or inject config.
        for name in tuple(child_env):
            if (name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_")
                    or name in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                                "GIT_CONFIG_PARAMETERS", "GIT_SSH", "GIT_SSH_COMMAND",
                                "GIT_EXEC_PATH", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD",
                                "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"}):
                child_env.pop(name, None)
        child_env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GH_HOST": "github.com",
            "GH_PROMPT_DISABLED": "1",
        })
        return child_env

    @staticmethod
    def _assert_safe_local_git_config(worktree: str, env: dict[str, str]) -> None:
        """Reject local settings that can execute programs during trusted Git commands."""
        configured = subprocess.check_output(
            ["git", "-C", worktree, "config", "--local", "--name-only", "--list"],
            cwd=worktree, env=env, text=True, stderr=subprocess.PIPE, timeout=30,
        ).splitlines()
        for raw in configured:
            key = raw.lower()
            suffix = key.rsplit(".", 1)[-1]
            if (key in {"core.fsmonitor", "core.sshcommand", "credential.helper", "core.pager",
                        "diff.external"}
                    or key.startswith("include.") or key.startswith("includeif.")
                    or key.startswith("url.") and suffix in {"insteadof", "pushinsteadof"}
                    or key.startswith("filter.") and suffix in {"smudge", "clean", "process"}
                    or key.startswith("remote.") and suffix in {"uploadpack", "receivepack"}
                    or key.startswith("submodule.") and suffix == "update"):
                raise RuntimeError("repository has executable local Git configuration")

    @staticmethod
    def _trusted_review_path(worktree: str) -> str:
        """Keep only absolute, owner-controlled PATH directories outside the reviewed tree."""
        repository = Path(worktree).resolve(strict=True)
        owners = {0, os.getuid()} if hasattr(os, "getuid") else {0}
        safe: list[str] = []
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            if not entry or not Path(entry).is_absolute():
                continue
            try:
                directory = Path(entry).resolve(strict=True)
            except OSError:
                continue
            if (not directory.is_dir() or directory == repository
                    or directory in repository.parents or repository in directory.parents):
                continue
            trusted = True
            for ancestor in (directory, *directory.parents):
                try:
                    info = ancestor.stat()
                except OSError:
                    trusted = False
                    break
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                        or stat.S_IMODE(info.st_mode) & 0o022):
                    trusted = False
                    break
            rendered = str(directory)
            if trusted and rendered not in safe:
                safe.append(rendered)
        path = os.pathsep.join(safe)
        if not path or not shutil.which("git", path=path):
            raise RuntimeError("trusted reviewer PATH is unavailable")
        return path

    @staticmethod
    def _validate_canonical_codex_home(raw_home: object, *, worktree: str) -> str:
        """Validate the policy-selected credential directory without reading secrets."""
        if not isinstance(raw_home, str) or not raw_home:
            raise RuntimeError("trusted reviewer policy omitted CODEX_HOME")
        home = Path(raw_home)
        if not home.is_absolute():
            raise RuntimeError("trusted reviewer CODEX_HOME must be absolute")
        try:
            resolved = home.resolve(strict=True)
            info = home.lstat()
            auth = home / "auth.json"
            auth_info = auth.lstat()
            repo = Path(worktree).resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("trusted reviewer CODEX_HOME or auth metadata is unavailable") from exc
        if resolved != home or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("trusted reviewer CODEX_HOME is not a canonical real directory")
        if (hasattr(os, "getuid") and info.st_uid != os.getuid()) or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("trusted reviewer CODEX_HOME must be owner-only")
        if (not stat.S_ISREG(auth_info.st_mode) or stat.S_ISLNK(auth_info.st_mode)
                or (hasattr(os, "getuid") and auth_info.st_uid != os.getuid())
                or stat.S_IMODE(auth_info.st_mode) != 0o600):
            raise RuntimeError("trusted reviewer authentication file must be owner-only")
        # Keep the credential directory disjoint from the reviewed worktree in
        # both directions.  A CODEX_HOME nested in the worktree could be
        # supplied by reviewed source, while a worktree nested in CODEX_HOME
        # would let delegated commands walk from the checkout to auth.json.
        if home == repo or home in repo.parents or repo in home.parents:
            raise RuntimeError("trusted reviewer CODEX_HOME must remain outside the reviewed repository")
        return str(home)

    def _canonical_codex_reviewer_policy(self, *, worktree: str, base: str) -> dict[str, str]:
        """Read reviewer settings from the byte-verified target policy module.

        The target policy remains the single authority for the canonical auth
        home, absolute executable, model, and reasoning effort. Only these
        non-secret values cross back into Harness; no credential data is read.
        """
        trusted = self._trusted_base_checkout(worktree, base)
        policy_query = (
            "import json,sys; from pathlib import Path; sys.path.insert(0,str(Path.cwd())); "
            "from scripts.devops.codex_reviewer_isolation import "
            "canonical_codex_binary,canonical_reviewer_environment; "
            "from scripts.devops.codex_review_contract import "
            "REVIEW_MODEL_PINNED,REVIEW_REASONING_EFFORT_PINNED; "
            "environment=canonical_reviewer_environment(source={}); "
            "binary=canonical_codex_binary(); "
            "print(json.dumps({'codex_home':environment.get('CODEX_HOME'),"
            "'codex_binary':str(binary),'model':REVIEW_MODEL_PINNED,"
            "'reasoning_effort':REVIEW_REASONING_EFFORT_PINNED}))"
        )
        result = self._call(
            [self._trusted_python_interpreter(), "-I", "-B", "-c", policy_query],
            cwd=str(trusted), env=self._trusted_git_environment(), inherit_environment=False,
        )
        policy = self._json_last_text(result.stdout)
        if result.returncode != 0 or not isinstance(policy, dict):
            raise RuntimeError("trusted canonical Codex reviewer policy could not be loaded")
        codex_binary = policy.get("codex_binary")
        model = policy.get("model")
        reasoning = policy.get("reasoning_effort")
        if (not isinstance(codex_binary, str) or not Path(codex_binary).is_absolute()
                or not isinstance(model, str) or re.fullmatch(r"[A-Za-z0-9_.:-]+", model) is None
                or reasoning not in {"low", "medium", "high", "xhigh"}):
            raise RuntimeError("trusted Codex reviewer executable or model provenance is invalid")
        return {
            "codex_home": self._validate_canonical_codex_home(policy.get("codex_home"), worktree=worktree),
            "codex_binary": codex_binary,
            "model": model,
            "reasoning_effort": reasoning,
        }

    def review_environment(self, reviewer: str, *, worktree: str,
                           base: str | None = None) -> dict[str, str]:
        """Build a restricted launcher environment for the trusted review wrapper."""
        if reviewer not in {"codex", "deepseek"}:
            raise ValueError(f"unsupported independent reviewer: {reviewer}")
        if reviewer == "codex":
            if not isinstance(base, str) or re.fullmatch(r"[0-9a-fA-F]{40}", base) is None:
                raise RuntimeError("canonical Codex reviewer environment requires an exact base SHA")
            codex_home = self._canonical_codex_reviewer_policy(
                worktree=worktree, base=base,
            )["codex_home"]
        else:
            codex_home = None
        environment = {
            "PATH": self._trusted_review_path(worktree),
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
        if codex_home is not None:
            environment["CODEX_HOME"] = codex_home
        for name in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        ):
            if name in os.environ:
                environment[name] = os.environ[name]
        ca_names = (
            "CODEX_CA_CERTIFICATE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
            "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE",
        )
        for name in ca_names:
            value = os.environ.get(name, "")
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

    def _trusted_base_checkout(self, worktree: str, base: str) -> Path:
        """Return only a registered, byte-verified worktree of the exact base."""
        if not isinstance(base, str) or re.fullmatch(r"[0-9a-fA-F]{40}", base) is None:
            raise RuntimeError("trusted base checkout requires a full base SHA")
        base = base.lower()
        candidate = Path(worktree).resolve(strict=True)
        root = candidate.parent / ".cmh-trusted-base" / base
        root_parent = root.parent
        if root_parent.is_symlink():
            raise RuntimeError("trusted base checkout parent is a symlink")
        root_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_info = root_parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode)
                or (hasattr(os, "getuid") and parent_info.st_uid != os.getuid())):
            raise RuntimeError("trusted base checkout parent is not owned by the current user")
        if stat.S_IMODE(parent_info.st_mode) & 0o077:
            root_parent.chmod(0o700)
            if stat.S_IMODE(root_parent.stat().st_mode) & 0o077:
                raise RuntimeError("trusted base checkout parent is not owner-only")

        self._assert_safe_local_git_config(str(candidate),
                                           self._trusted_subprocess_environment())

        if not root.exists() and not root.is_symlink():
            added = self._call([
                "git", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
                "-c", "core.fsmonitor=false", "--no-replace-objects", "worktree", "add",
                "--detach", str(root), base,
            ], cwd=str(candidate), env=self._trusted_git_environment(), inherit_environment=False)
            if added.returncode != 0:
                raise RuntimeError(added.stderr.strip() or "cannot create trusted base checkout")
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            raise RuntimeError("trusted base checkout path is not a real directory")

        listing = self._trusted_git_output(candidate, "worktree", "list", "--porcelain")
        records: list[dict[str, str | bool]] = []
        record: dict[str, str | bool] = {}
        for line in listing.splitlines() + [""]:
            if not line:
                if record:
                    records.append(record)
                    record = {}
            elif line.startswith("worktree "):
                record["worktree"] = line[len("worktree "):]
            elif line.startswith("HEAD "):
                record["head"] = line[len("HEAD "):].lower()
            elif line == "detached":
                record["detached"] = True
        matching = [item for item in records
                    if isinstance(item.get("worktree"), str)
                    and Path(str(item["worktree"])).resolve() == root.resolve()]
        if len(matching) != 1 or matching[0].get("head") != base or not matching[0].get("detached"):
            raise RuntimeError("trusted base checkout is not the registered detached worktree for this repository")

        candidate_common = Path(self._trusted_git_output(
            candidate, "rev-parse", "--path-format=absolute", "--git-common-dir",
        ).strip()).resolve()
        trusted_common = Path(self._trusted_git_output(
            root, "rev-parse", "--path-format=absolute", "--git-common-dir",
        ).strip()).resolve()
        git_file = root / ".git"
        git_file_info = git_file.lstat()
        if not stat.S_ISREG(git_file_info.st_mode) or stat.S_ISLNK(git_file_info.st_mode):
            raise RuntimeError("trusted base checkout has no regular linked-worktree metadata file")
        git_file_lines = git_file.read_text(encoding="utf-8").splitlines()
        if len(git_file_lines) != 1 or not git_file_lines[0].startswith("gitdir: "):
            raise RuntimeError("trusted base checkout worktree link is malformed")
        admin_dir = Path(git_file_lines[0][len("gitdir: "):])
        if not admin_dir.is_absolute():
            admin_dir = root / admin_dir
        admin_dir = admin_dir.resolve(strict=True)
        worktrees_dir = (candidate_common / "worktrees").resolve()
        try:
            admin_dir.relative_to(worktrees_dir)
        except ValueError as exc:
            raise RuntimeError("trusted base checkout is linked to another Git repository") from exc
        back_link = admin_dir / "gitdir"
        if (back_link.is_symlink() or not back_link.is_file()
                or Path(back_link.read_text(encoding="utf-8").strip()).resolve() != git_file.resolve()):
            raise RuntimeError("trusted base checkout worktree back-link is invalid")
        if candidate_common != trusted_common:
            raise RuntimeError("trusted base checkout uses another Git common directory")

        observed = self._trusted_git_output(
            root, "-c", "core.fsmonitor=false", "rev-parse", "HEAD",
        ).strip().lower()
        dirty = self._trusted_git_output(
            root, "-c", "core.fsmonitor=false", "status",
            "--porcelain=v1", "--untracked-files=all",
        )
        if observed != base or dirty:
            raise RuntimeError("trusted base checkout identity is invalid")
        self._verify_trusted_policy_sources(candidate, root, base)
        return root

    def _verify_trusted_policy_sources(self, candidate: Path, trusted: Path, base: str) -> None:
        tree = self._trusted_git_output(
            candidate, "ls-tree", "-rz", "--full-tree", base,
            "--", "scripts", *self.REVIEW_CONTRACT_PATHS,
        )
        blobs: dict[str, tuple[str, str]] = {}
        for item in tree.split("\0"):
            if not item:
                continue
            try:
                metadata, relative = item.split("\t", 1)
                mode, kind, oid = metadata.split(" ", 2)
            except ValueError as exc:
                raise RuntimeError("trusted review policy tree is malformed") from exc
            if kind == "blob":
                blobs[relative] = (mode, oid)
            elif relative.startswith("scripts/"):
                raise RuntimeError("trusted review policy tree contains a non-blob script entry")
        if not set(self.REVIEW_CONTRACT_PATHS) <= set(blobs):
            raise RuntimeError("trusted base is missing a required review policy source")

        expected_scripts = {path for path in blobs if path.startswith("scripts/")}
        scripts_root = trusted / "scripts"
        if not scripts_root.is_dir():
            raise RuntimeError("trusted base has no scripts directory")
        observed_scripts: set[str] = set()
        for directory, names, filenames in os.walk(scripts_root, followlinks=False):
            for name in names:
                if (Path(directory) / name).is_symlink():
                    raise RuntimeError("trusted base scripts contain a symlink directory")
            for filename in filenames:
                source = Path(directory) / filename
                observed_scripts.add(source.relative_to(trusted).as_posix())
        if observed_scripts != expected_scripts:
            raise RuntimeError("trusted base scripts differ from the committed policy tree")

        for relative in sorted(expected_scripts | set(self.REVIEW_CONTRACT_PATHS)):
            mode, oid = blobs[relative]
            source = trusted / relative
            info = source.lstat()
            if mode == "120000" or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeError("trusted base policy source is not a regular committed file")
            if bool(info.st_mode & 0o111) != (mode == "100755"):
                raise RuntimeError("trusted base policy source mode differs from the commit")
            contents = source.read_bytes()
            git_blob = hashlib.sha1(
                f"blob {len(contents)}\0".encode("ascii") + contents,
                usedforsecurity=False,
            ).hexdigest()
            if git_blob != oid:
                raise RuntimeError("trusted base policy source content differs from the commit")

    def review_argv(self, reviewer: str, *, worktree: str, base: str, head: str, mission_id: str,
                    scope_file: str, evidence_dir: str, attempt_id: str) -> list[str]:
        expected_evidence = self.review_evidence_dir(worktree, mission_id, reviewer, head)
        if Path(evidence_dir).resolve(strict=False) != expected_evidence.resolve(strict=False):
            raise ValueError("review evidence directory does not match the exact mission/reviewer/HEAD")
        self._validate_review_evidence_dir(expected_evidence)
        if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
            raise ValueError("review attempt identity must be 32 lowercase hexadecimal characters")
        trusted = self._trusted_base_checkout(worktree, base)
        common = ["--repo-root", worktree, "--base-sha", base, "--head-sha", head,
                  "--mission-id", mission_id, "--mission-scope-file", scope_file,
                  "--evidence-dir", evidence_dir]
        python = self._trusted_python_interpreter()
        if reviewer == "codex":
            return [python, "-I", "-B",
                    str(trusted / "scripts/devops/codex_independent_review.py"), "run", *common,
                    "--run-id", attempt_id, "--json"]
        if reviewer == "deepseek":
            return [python, "-I", "-B",
                    str(trusted / "scripts/devops/claude_deepseek_independent_review.py"), *common]
        raise ValueError(f"unsupported independent reviewer: {reviewer}")

    def review(self, reviewer: str, head: str) -> GateResult:
        """Compatibility guard: production review needs bound scope/context.

        Supervisor v0.1 callers cannot supply those mandatory canonical inputs,
        so this path refuses rather than manufacturing a receipt.
        """
        return GateResult("BLOCKED_EXTERNAL", "review requires mission_scope_file and exact base/worktree context")

    @staticmethod
    def _read_private_review_log(path: Path) -> tuple[bytes, str] | None:
        """Read and hash one owner-only review log without following links."""
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            return None
        try:
            fd = os.open(path, os.O_RDONLY | nofollow)
        except OSError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or (hasattr(os, "getuid") and info.st_uid != os.getuid())
                    or stat.S_IMODE(info.st_mode) & 0o077):
                return None
            if info.st_size > 512 * 1024 * 1024:
                return None
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                digest = hashlib.sha256()
                tail = bytearray()
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                    tail.extend(chunk)
                    if len(tail) > 8 * 1024 * 1024:
                        del tail[:-8 * 1024 * 1024]
            return bytes(tail), digest.hexdigest()
        except OSError:
            return None
        finally:
            if fd >= 0:
                os.close(fd)

    def _deepseek_wrapper_failure(
        self, payload: dict[str, Any], *, evidence_dir: Path, mission_id: str,
        base: str, head: str, repository: str, current_attempt_id: str | None,
    ) -> dict[str, Any] | None:
        """Accept a DeepSeek typed failure only with its exact private sidecar."""
        try:
            classification = ReviewFailureClassification(payload.get("failure_classification"))
        except (TypeError, ValueError):
            return None
        retryable = payload.get("retryable")
        evidence_path = payload.get("failure_evidence_path")
        expected_sha = payload.get("failure_evidence_sha256")
        if (payload.get("status") != "BLOCKED_EXTERNAL"
                or not isinstance(retryable, bool) or retryable != classification.retryable
                or not isinstance(evidence_path, str) or not Path(evidence_path).is_absolute()
                or not isinstance(expected_sha, str)
                or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None):
            return None

        path = Path(evidence_path)
        if (path.is_symlink() or path.name.startswith(".")
                or not path.name.startswith("review-attempt-failure-")
                or path.suffix != ".json"):
            return None
        try:
            expected_root = evidence_dir.resolve(strict=True)
            parent = path.parent
            parent_info = parent.lstat()
            if (stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode)
                    or (hasattr(os, "getuid") and parent_info.st_uid != os.getuid())
                    or stat.S_IMODE(parent_info.st_mode) != 0o700
                    or parent.resolve(strict=True).parent != expected_root
                    or path.resolve(strict=True).parent != parent.resolve(strict=True)):
                return None
        except OSError:
            return None

        private_artifact = self._read_private_review_log(path)
        if private_artifact is None or private_artifact[1] != expected_sha:
            return None
        try:
            record = json.loads(private_artifact[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(record, dict):
            return None
        integrity = record.get("integrity_sha256")
        unsigned = {key: value for key, value in record.items() if key != "integrity_sha256"}
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        if (not isinstance(integrity, str)
                or not hmac.compare_digest(hashlib.sha256(canonical).hexdigest(), integrity)):
            return None

        attempt_id = record.get("attempt_id")
        diff_sha = record.get("diff_sha256")
        record_repository = record.get("repository")
        record_remote = urlsplit(record_repository) if isinstance(record_repository, str) else None
        record_parts = (record_remote.path.strip("/").split("/")
                        if record_remote is not None else [])
        record_identity = None
        if (record_remote is not None and record_remote.hostname is not None
                and record_remote.hostname.lower() == "github.com"
                and record_remote.scheme in {"https", "ssh"}
                and record_remote.username is None and record_remote.password is None
                and not record_remote.query and not record_remote.fragment
                and len(record_parts) == 2):
            record_owner, record_name = record_parts
            if record_name.endswith(".git"):
                record_name = record_name[:-4]
            record_identity = f"{record_owner}/{record_name}"
        if (record.get("schema_version") != "cmh-review-attempt-failure/v1"
                or record.get("provider") != "deepseek"
                or record.get("model") != "deepseek-flash"
                or record_identity != repository
                or record.get("mission_id") != mission_id
                or record.get("base_sha") != base.lower()
                or record.get("head_sha") != head.lower()
                or not isinstance(attempt_id, str)
                or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None
                or attempt_id != current_attempt_id
                or path.parent.name != attempt_id
                or not isinstance(diff_sha, str)
                or re.fullmatch(r"[0-9a-f]{64}", diff_sha) is None
                or record.get("failure_classification") != classification.value
                or record.get("retryable") is not retryable
                or record.get("receipt_written") is not False):
            return None
        return {
            "status": "BLOCKED_EXTERNAL",
            "failure_classification": classification.value,
            "retryable": retryable,
            "reason_code": record.get("reason_code"),
            "stage": record.get("stage"),
            "attempt_id": attempt_id,
            "failure_evidence_path": str(path),
            "failure_evidence_sha256": expected_sha,
            "diff_sha256": diff_sha,
        }

    @staticmethod
    def _review_error_fields(value: object) -> list[str]:
        """Extract only provider error fields from a structured failure event."""
        fields: list[str] = []
        if isinstance(value, dict):
            status_names = {"status", "status_code", "http_status", "statuscode", "httpstatus"}
            for name in ("code", "type", "status", "status_code", "http_status",
                         "statusCode", "httpStatus", "message"):
                item = value.get(name)
                if isinstance(item, (str, int)) and not isinstance(item, bool):
                    rendered = str(item)
                    if name.casefold() in status_names:
                        normalized_status = rendered.strip()
                        status_text = (normalized_status[5:].strip()
                                       if normalized_status[:5].casefold() == "http "
                                       else normalized_status)
                        if (len(status_text) == 3 and status_text.isdigit()
                                and status_text[0] in "12345"):
                            rendered = f"HTTP {status_text}"
                    fields.append(rendered)
            nested = value.get("error")
            if isinstance(nested, (dict, str)):
                fields.extend(FootballPredictionAdapter._review_error_fields(nested))
        elif isinstance(value, str):
            fields.append(value)
        return fields

    def _receiptless_review_failure(
        self, *, reviewer: str, worktree: str, base: str, head: str, mission_id: str,
        evidence_dir: Path, attempt_id: str | None, stdout_path: str, stderr_path: str | None,
        terminal_status: str | None, exit_code: int | None, contract_failure: bool = False,
    ) -> GateResult:
        """Persist a sanitized typed result when a review ends without a receipt."""
        repository = "unknown/unknown"
        try:
            repository = self._repo_from_origin(worktree)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass

        # A receiptless failure cannot establish an executed model. At most
        # record a successfully resolved current policy; never revive old pins.
        model, reasoning = "unknown", None
        codex_home: str | None = None
        codex_binary: str | None = None
        if reviewer == "codex":
            if not contract_failure:
                try:
                    policy = self._canonical_codex_reviewer_policy(worktree=worktree, base=base)
                    codex_home = policy["codex_home"]
                    codex_binary = policy["codex_binary"]
                    model = policy["model"]
                    reasoning = policy["reasoning_effort"]
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                    pass

        events_path: Path | None = None
        codex_stderr_path: Path | None = None
        signal_sources: list[str] = []
        if (reviewer == "codex" and isinstance(attempt_id, str)
                and re.fullmatch(r"[0-9a-f]{32}", attempt_id)):
            events_path = evidence_dir / f"codex-review-output-{head[:12]}-{attempt_id}.jsonl"
            codex_stderr_path = evidence_dir / f"codex-review-stderr-{head[:12]}-{attempt_id}.log"

        event_log = self._read_private_review_log(events_path) if events_path else None
        reviewer_stderr = self._read_private_review_log(codex_stderr_path) if codex_stderr_path else None
        process_stdout = self._read_private_review_log(Path(stdout_path))
        process_stderr = self._read_private_review_log(Path(stderr_path)) if stderr_path else None

        turn_completed = False
        signals: list[str] = []
        if event_log is not None:
            raw_events = event_log[0]
            for line in raw_events.splitlines():
                try:
                    event = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(event, dict):
                    continue
                event_type = event.get("type")
                if event_type == "turn.completed":
                    turn_completed = True
                elif event_type in {"turn.failed", "error"}:
                    # Codex versions emit both nested errors and flat error
                    # events (for example {"type":"error","code":...}).
                    # Read only the allowlisted diagnostic fields and bind
                    # them together so structured status/code pairs classify.
                    error_event = {key: value for key, value in event.items() if key != "type"}
                    error_fields = self._review_error_fields(error_event)
                    if error_fields:
                        signals.append(" ".join(error_fields))
                        signal_sources.append("codex_jsonl:" + str(event_type))

        if reviewer_stderr is not None:
            try:
                signals.append(reviewer_stderr[0].decode("utf-8", errors="replace"))
                signal_sources.append("codex_stderr")
            except UnicodeDecodeError:
                pass
        if process_stderr is not None:
            # The outer process log can contain a CLI/provider diagnostic even
            # when Codex emitted no JSONL error event. It is inspected in
            # memory; only its hash and the normalized classification below
            # are persisted.
            signals.append(process_stderr[0].decode("utf-8", errors="replace"))
            signal_sources.append("process_stderr")

        # The trusted wrapper's --json failure object is a structured terminal
        # record. Ordinary reviewer text and untyped JSON never enter the
        # classifier.
        wrapper_failure: dict[str, Any] = {}
        typed_wrapper_failure: dict[str, Any] | None = None
        if process_stdout is not None:
            try:
                wrapper_payload = self._json_last_text(process_stdout[0].decode("utf-8", errors="replace"))
            except (UnicodeDecodeError, ValueError):
                wrapper_payload = {}
            if (isinstance(wrapper_payload, dict)
                    and wrapper_payload.get("status") in {"FAIL", "BLOCKED_EXTERNAL"}
                    and isinstance(wrapper_payload.get("error"), str)):
                wrapper_failure = {"status": str(wrapper_payload["status"])}
                if reviewer != "deepseek":
                    signals.append(wrapper_payload["error"])
                    signal_sources.append("trusted_wrapper_json_error")
                elif wrapper_payload.get("status") == "BLOCKED_EXTERNAL":
                    try:
                        repository = self._repo_from_origin(worktree)
                    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                        repository = "unknown/unknown"
                    typed_wrapper_failure = self._deepseek_wrapper_failure(
                        wrapper_payload, evidence_dir=evidence_dir, mission_id=mission_id,
                        base=base, head=head, repository=repository,
                        current_attempt_id=attempt_id,
                    )
                    if typed_wrapper_failure is not None:
                        wrapper_failure = typed_wrapper_failure
                        signal_sources.append("validated_deepseek_failure_artifact")

        failure_details = None
        if contract_failure or turn_completed:
            classification = ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE
            reason_code = ("invalid_receipt_binding" if contract_failure
                           else "completed_turn_without_valid_receipt")
            failure_details = classify_process_failure(["review contract rejected"])
        elif typed_wrapper_failure is not None:
            classification = ReviewFailureClassification(
                typed_wrapper_failure["failure_classification"],
            )
            reason_code = str(typed_wrapper_failure.get("reason_code") or "deepseek_attempt_failed")
        else:
            classification = ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE
            reason_code = "unclassified_external_failure"
            failure_details = classify_process_failure([])
            # Prefer non-retryable categories if conflicting diagnostics were
            # captured; only clean capacity/transport evidence may retry.
            for category in (
                ReviewFailureClassification.AUTHENTICATION_FAILURE,
                ReviewFailureClassification.PAYMENT_OR_BILLING_FAILURE,
                ReviewFailureClassification.MODEL_UNAVAILABLE_OR_UNSUPPORTED,
                ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
                ReviewFailureClassification.TRANSIENT_CAPACITY,
                ReviewFailureClassification.TRANSIENT_TRANSPORT,
            ):
                match = next((details for signal in signals
                              if (details := classify_process_failure([signal])).classification == category), None)
                if match is not None:
                    classification, reason_code = match.classification, match.reason_code
                    failure_details = match
                    break

        event_artifact = None
        if event_log is not None and events_path is not None:
            event_artifact = {"path": str(events_path), "sha256": event_log[1]}
        codex_stderr_artifact = None
        if reviewer_stderr is not None and codex_stderr_path is not None:
            codex_stderr_artifact = {"path": str(codex_stderr_path), "sha256": reviewer_stderr[1]}
        failure_record = {
            "schema_version": "cmh-review-attempt-failure/v1",
            "repository": repository,
            "mission_id": mission_id,
            "base_sha": base.lower(),
            "head_sha": head.lower(),
            "reviewer": reviewer,
            "model": model,
            "reasoning_effort": reasoning,
            "codex_home": codex_home,
            "codex_binary": codex_binary,
            "stage": "review",
            "attempt_id": attempt_id,
            "terminal_status": terminal_status or "UNKNOWN",
            "exit_code": exit_code,
            "process_succeeded": exit_code == 0,
            "failure_phase": (
                "REVIEW_CONTRACT_VALIDATION" if contract_failure or turn_completed
                else "PROCESS_OR_PROVIDER"
            ),
            "turn_completed": turn_completed,
            "wrapper_failure": wrapper_failure,
            "failure_classification": classification.value,
            "retryable": classification.retryable,
            "reason_code": reason_code,
            "sanitized_diagnostic": (failure_details.sanitized_diagnostic
                                     if failure_details is not None else None),
            "http_status": failure_details.http_status if failure_details is not None else None,
            "provider_error_code": (failure_details.provider_error_code
                                    if failure_details is not None else None),
            "signal_sources": sorted(set(signal_sources)),
            "event_log": event_artifact,
            "codex_stderr_log": codex_stderr_artifact,
            "process_stdout_sha256": process_stdout[1] if process_stdout is not None else None,
            "process_stderr_sha256": process_stderr[1] if process_stderr is not None else None,
        }
        attempt_component = attempt_id if isinstance(attempt_id, str) and re.fullmatch(
            r"[0-9a-f]{32}", attempt_id,
        ) else hashlib.sha256(f"{mission_id}:{head}:{terminal_status}:{exit_code}".encode()).hexdigest()[:32]
        record_path = evidence_dir / f"attempt-failure-{attempt_component}.json"
        rendered = json.dumps(failure_record, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            self._write_private_file(record_path, rendered, exclusive=True)
        except (OSError, RuntimeError):
            return GateResult(
                "BLOCKED_EXTERNAL", "receipt-less reviewer failure evidence could not be persisted",
                failure_classification=ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE,
            )
        evidence_sha256 = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
        data = {
            "failure_classification": classification.value,
            "retryable": classification.retryable,
            "failure_evidence_path": str(record_path),
            "failure_evidence_sha256": evidence_sha256,
            "wrapper_failure": wrapper_failure,
            "event_log": event_artifact,
            "codex_stderr_log": codex_stderr_artifact,
        }
        return GateResult(
            "BLOCKED_EXTERNAL",
            f"receipt-less reviewer attempt classified as {classification.value}; "
            f"failure evidence {record_path} sha256={evidence_sha256}",
            data=data,
            failure_classification=classification,
        )

    def review_result(self, reviewer: str, *, worktree: str, base: str, head: str, mission_id: str,
                      scope_file: str, stdout_path: str, evidence_dir: str,
                      attempt_id: str | None = None, terminal_status: str | None = None,
                      exit_code: int | None = None, stderr_path: str | None = None) -> GateResult:
        """Accept only a canonical receipt, revalidated against exact inputs."""
        preflight = self.review_preflight(worktree, base, head)
        if preflight.status != "PASS":
            return preflight
        payload = self._json_last_line(stdout_path)
        receipt = payload.get("review_receipt") if isinstance(payload, dict) else None
        try:
            expected_evidence = self.review_evidence_dir(worktree, mission_id, reviewer, head)
            if Path(evidence_dir).resolve(strict=True) != expected_evidence.resolve(strict=True):
                raise RuntimeError("review evidence directory does not match exact inputs")
            expected_evidence = self._validate_review_evidence_dir(expected_evidence)
        except (OSError, RuntimeError, TypeError, ValueError):
            return GateResult(
                "BLOCKED_EXTERNAL", "canonical review evidence directory is unavailable",
                failure_classification=ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE,
            )
        if not isinstance(receipt, str):
            return self._receiptless_review_failure(
                reviewer=reviewer, worktree=worktree, base=base, head=head,
                mission_id=mission_id, evidence_dir=expected_evidence,
                attempt_id=attempt_id, stdout_path=stdout_path, stderr_path=stderr_path,
                terminal_status=terminal_status, exit_code=exit_code,
            )
        try:
            receipt_path = Path(receipt)
            if (not receipt_path.is_absolute()
                    or receipt_path.parent.resolve(strict=True) != expected_evidence
                    or receipt_path.is_symlink()
                    or not stat.S_ISREG(receipt_path.lstat().st_mode)):
                raise RuntimeError("reviewer receipt is outside the prevalidated evidence directory")
        except (OSError, RuntimeError, TypeError, ValueError):
            return self._receiptless_review_failure(
                reviewer=reviewer, worktree=worktree, base=base, head=head,
                mission_id=mission_id, evidence_dir=expected_evidence,
                attempt_id=attempt_id, stdout_path=stdout_path, stderr_path=stderr_path,
                terminal_status=terminal_status, exit_code=exit_code, contract_failure=True,
            )
        receipt = str(receipt_path)
        if reviewer == "codex":
            trusted = self._trusted_base_checkout(worktree, base)
            argv = [self._trusted_python_interpreter(), "-I", "-B", str(trusted / "scripts/devops/codex_independent_review.py"), "classify", "--repo-root", worktree,
                    "--receipt", receipt, "--current-head", head, "--base-sha", base, "--mission-id", mission_id,
                    "--mission-scope-file", scope_file, "--json"]
        elif reviewer == "deepseek":
            # Project-owned validator verifies aggregate/chunk evidence.  The
            # reviewer receives embedded diff chunks, not repository tools.
            # The runner validates the chunk aggregate before its commit-last
            # receipt write. Verify the durable binding again here without
            # inventing a competing review protocol.
            try:
                evidence = json.loads(Path(receipt).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return GateResult("BLOCKED_EXTERNAL", "DeepSeek receipt is unreadable", receipt)
            if not isinstance(evidence, dict):
                return GateResult("BLOCKED_EXTERNAL", "DeepSeek receipt is not a JSON object", receipt)
            if evidence.get("receipt_version") == "independent-review-receipt/v1":
                trusted = self._trusted_base_checkout(worktree, base)
                # Re-run the target's canonical evidence consumer. Its code is
                # accepted only after review_preflight proves it is unchanged
                # from the trusted base.
                required = {"receipt_version", "base_sha", "head_sha", "mission_id", "diff_sha256", "review_result", "findings", "integrity"}
            else:
                return GateResult("BLOCKED_EXTERNAL", "unknown DeepSeek receipt contract", receipt)
            if not required <= set(evidence) or evidence.get("base_sha") != base or evidence.get("head_sha") != head or evidence.get("mission_id") != mission_id:
                return GateResult("BLOCKED_EXTERNAL", "DeepSeek receipt binding is incomplete or stale", receipt)
            if evidence.get("receipt_version") == "independent-review-receipt/v1":
                try:
                    relative_scope = Path(scope_file).resolve().relative_to(Path(worktree).resolve()).as_posix()
                    scope_bytes = self._trusted_git_output(
                        Path(worktree), "show", f"{head}:{relative_scope}"
                    ).encode("utf-8")
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    return GateResult("BLOCKED_EXTERNAL", f"cannot bind reviewed mission scope: {exc}", receipt)
                scope_hash = hashlib.sha256(scope_bytes).hexdigest()
                validator = (
                    "from dataclasses import asdict; import json,os,sys; from pathlib import Path; "
                    "sys.path.insert(0,os.getcwd()); "
                    "from scripts.devops.deepseek_receipt_evidence import _deepseek_receipt_evidence as v; "
                    "print(json.dumps(asdict(v(Path(sys.argv[1]),repo_root=Path(sys.argv[2]),"
                    "expected_base=sys.argv[3],expected_head=sys.argv[4],expected_mission_id=sys.argv[5],expected_scope_hash=sys.argv[6]))))"
                )
                validator_env = self._trusted_git_environment()
                validator_env["PYTHONDONTWRITEBYTECODE"] = "1"
                checked = self._call(
                    [self._trusted_python_interpreter(), "-I", "-B", "-c", validator,
                     receipt, worktree, base, head, mission_id, scope_hash],
                    cwd=str(trusted), env=validator_env, inherit_environment=False,
                )
                canonical = self._json_last_text(checked.stdout)
                if (checked.returncode != 0 or not isinstance(canonical, dict)
                        or canonical.get("trusted") is not True):
                    return GateResult("BLOCKED_EXTERNAL", checked.stderr.strip() or "canonical DeepSeek receipt validation failed", receipt)
                if canonical.get("result") != evidence.get("review_result"):
                    return GateResult("BLOCKED_EXTERNAL", "canonical DeepSeek verdict mismatch", receipt)
            findings = evidence.get("findings")
            if not isinstance(findings, list) or not all(isinstance(finding, dict) for finding in findings):
                return GateResult("BLOCKED_EXTERNAL", "DeepSeek receipt findings are malformed", receipt)
            blocking = any(finding.get("severity") in {"P0", "P1", "P2"} for finding in findings)
            if evidence.get("review_result") != "PASS" or blocking:
                return GateResult("FAIL", "canonical DeepSeek receipt reports findings", receipt, evidence)
            return GateResult("PASS", "canonical DeepSeek aggregate receipt validated", receipt, evidence)
        else: return GateResult("BLOCKED_EXTERNAL", f"unknown reviewer {reviewer}")
        # The classifier is policy code from the trusted base checkout.  Its
        # imports must resolve there, never from the candidate HEAD worktree.
        result = self._call(
            argv, cwd=str(trusted),
            env=self.review_environment(reviewer, worktree=worktree, base=base),
            inherit_environment=False,
        )
        if result.returncode != 0:
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or result.stdout.strip(), receipt)
        classification = self._json_last_text(result.stdout)
        if (not isinstance(classification, dict)
                or not isinstance(classification.get("classification"), dict)
                or classification["classification"].get("classification") != "VALID_CURRENT"):
            return GateResult("BLOCKED_EXTERNAL", "canonical Codex receipt is not VALID_CURRENT", receipt, classification)
        validated = classification.get("receipt")
        verdict = validated.get("review_result") if isinstance(validated, dict) else None
        if verdict not in {"PASS", "FAIL"}:
            return GateResult("BLOCKED_EXTERNAL", "canonical Codex classifier omitted a valid receipt verdict", receipt, classification)
        if verdict == "FAIL":
            return GateResult("FAIL", "canonical receipt reports findings", receipt, validated)
        return GateResult("PASS", "canonical exact-head receipt validated", receipt, validated)

    def discover_pr(self, worktree: str, head: str) -> GateResult:
        try:
            repo = self._repo_from_origin(worktree)
            branch = self._run(["git", "branch", "--show-current"], cwd=worktree).strip()
            if not branch:
                return GateResult("BLOCKED_EXTERNAL", "GitHub PR discovery requires a named branch")
            owner = repo.split("/", 1)[0]
            head_filter = quote(f"{owner}:{branch}", safe="")
            pulls = json.loads(self._run(self._gh(
                "api", f"repos/{repo}/pulls?state=open&head={head_filter}",
            ), cwd=worktree))
            if not isinstance(pulls, list) or not all(isinstance(pull, dict) for pull in pulls):
                return GateResult("BLOCKED_EXTERNAL", "GitHub PR discovery returned an invalid response")
        except (subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"GitHub PR discovery unavailable: {exc}", data={"retryable": True})
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"GitHub PR discovery returned invalid evidence: {exc}")
        matches = []
        for pull in pulls:
            pull_head, pull_base = pull.get("head"), pull.get("base")
            if not isinstance(pull_head, dict) or not isinstance(pull_base, dict):
                continue
            if (pull_head.get("sha") == head.lower()
                    and pull_head.get("ref") == branch
                    and pull_base.get("ref") == "main"):
                matches.append(pull)
        if len(matches) == 0:
            return GateResult("BLOCKED_EXTERNAL", f"no open PR for branch={branch} head={head}; publication may still be pending",
                              data={"retryable": True, "branch": branch, "head": head.lower()})
        if len(matches) != 1:
            return GateResult("BLOCKED_EXTERNAL", f"expected one open PR for branch={branch} head={head}; found {len(matches)}")
        number = matches[0].get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            return GateResult("BLOCKED_EXTERNAL", "GitHub PR discovery omitted a valid PR number")
        base_sha = str((matches[0].get("base") or {}).get("sha", "")).lower()
        if re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
            return GateResult("BLOCKED_EXTERNAL", "GitHub PR discovery omitted an exact base SHA")
        return GateResult("PASS", f"PR #{number}", data={
            "number": number, "repo": repo, "head": head.lower(),
            "base": "main", "state": "OPEN",
            "base_sha": base_sha,
        })

    def _repo_from_origin(self, worktree: str) -> str:
        """Derive GitHub identity from this checkout's origin, not ambient gh config."""
        remote = self._run(
            ["git", "remote", "get-url", "origin"], cwd=worktree,
        ).strip()
        if "://" in remote:
            parsed = urlsplit(remote)
            host, path = parsed.hostname, parsed.path
        elif remote.startswith("git@") and ":" in remote:
            host, path = remote.split("@", 1)[1].split(":", 1)
        else:
            raise ValueError("origin is not a supported GitHub remote")
        if host is None or host.lower() != "github.com":
            raise ValueError("origin does not identify github.com")
        parts = path.strip("/").split("/")
        if len(parts) != 2:
            raise ValueError("origin does not identify one GitHub repository")
        owner, name = parts
        if name.endswith(".git"):
            name = name[:-4]
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+", owner)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                or owner in {".", ".."} or name in {".", ".."}):
            raise ValueError("origin does not identify one GitHub repository")
        return f"{owner}/{name}"

    def ci(self, worktree: str, head: str, pr_number: int | None = None,
           pr_repo: str | None = None, base_sha: str | None = None,
           pr_base_sha: str | None = None) -> GateResult:
        # CI evidence is an authority boundary.  Without an immutable base
        # checkout there is no trusted copy of the project's PR-readiness
        # command, so never execute a candidate-controlled Makefile as a
        # fallback or interpret its stdout as GitHub truth.
        if not base_sha:
            return GateResult("BLOCKED_EXTERNAL", "canonical CI requires an exact trusted base SHA")
        if pr_number is None:
            pr = self.discover_pr(worktree, head)
            if pr.status != "PASS": return pr
            facts = pr.data if isinstance(pr.data, dict) else {}
            pr_number, pr_repo = facts.get("number"), facts.get("repo")
            if (not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0
                    or not isinstance(pr_repo, str) or not re.fullmatch(
                        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pr_repo)):
                return GateResult("BLOCKED_EXTERNAL", "PR discovery returned an invalid durable identity")
            bound = self._pr_state(worktree, pr_number, pr_repo)
            bound_facts = bound.data or {}
            if (bound.status != "PASS" or bound_facts.get("head") != head.lower()
                    or bound_facts.get("base") != "main" or bound_facts.get("state") != "OPEN"
                    or re.fullmatch(r"[0-9a-f]{40}", str(bound_facts.get("base_sha", ""))) is None):
                return GateResult("BLOCKED_EXTERNAL", f"discovered PR #{pr_number} is no longer open at exact HEAD {head}")
        else:
            if not pr_repo: return GateResult("BLOCKED_EXTERNAL", "durable PR identity has no repository")
            bound = self._pr_state(worktree, pr_number, pr_repo)
            if bound.status != "PASS": return bound
            facts = bound.data or {}
            if (facts.get("head") != head.lower() or facts.get("base") != "main"
                    or facts.get("state") != "OPEN"
                    or re.fullmatch(r"[0-9a-f]{40}", str(facts.get("base_sha", ""))) is None):
                return GateResult("BLOCKED_EXTERNAL", f"durable PR #{pr_number} no longer matches open main PR at {head}")
        observed_base_sha = str((bound.data or {}).get("base_sha", "")).lower()
        if observed_base_sha != base_sha.lower():
            return GateResult(
                "BLOCKED_EXTERNAL",
                "current PR base SHA differs from the trusted policy base SHA",
            )
        if pr_base_sha is not None and observed_base_sha != pr_base_sha.lower():
            return GateResult("BLOCKED_EXTERNAL", "durable PR base SHA changed after review/approval")
        try:
            trusted = self._trusted_base_checkout(
                worktree, base_sha,
            )
            code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                    "from scripts.devops import pr_ready_check as m; m.ROOT=Path(sys.argv[2]); "
                    "sys.argv=['pr-ready-check','--pr',sys.argv[3],'--json']; raise SystemExit(m.main())")
            result = self._call(
                ["python3", "-I", "-B", "-c", code, str(trusted), worktree, str(pr_number)],
                cwd=str(trusted), env={"GH_REPO": pr_repo, "GH_HOST": "github.com", "PYTHONDONTWRITEBYTECODE": "1"},
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"trusted PR readiness unavailable: {exc}")
        try: data = self._json_document_prefix(result.stdout)
        except json.JSONDecodeError: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "canonical pr-ready returned no JSON")
        pr_data = data.get("pr")
        findings = data.get("findings")
        if (not isinstance(pr_data, dict) or not isinstance(findings, list)
                or not all(isinstance(finding, dict) for finding in findings)):
            return GateResult("BLOCKED_EXTERNAL", "canonical pr-ready returned malformed PR/check evidence")
        data["pr_number"] = pr_number
        data["pr_repo"] = pr_repo
        observed = str(pr_data.get("head_sha", "")).lower()
        if observed != head.lower(): return GateResult("BLOCKED_EXTERNAL", f"PR HEAD {observed or 'MISSING'} does not equal {head}")
        checks = [finding for finding in findings
                  if str(finding.get("name", "")).startswith("required-check:")]
        if not checks: return GateResult("BLOCKED_EXTERNAL", "canonical pr-ready reported no required checks")
        messages = "\n".join(str(f.get("message", "")) for f in checks)
        data["pr_base_sha"] = observed_base_sha
        if (result.returncode == 0 and data.get("verdict") == "PASS"
                and all(f.get("passed") is True for f in checks)):
            final_pr = self._pr_state(worktree, pr_number, pr_repo)
            final_facts = final_pr.data if isinstance(final_pr.data, dict) else {}
            if (final_pr.status != "PASS" or final_facts.get("head") != head.lower()
                    or final_facts.get("base") != "main" or final_facts.get("state") != "OPEN"
                    or final_facts.get("base_sha") != observed_base_sha):
                return GateResult("BLOCKED_EXTERNAL", "PR identity or base changed while exact-head CI was checked")
            return GateResult("PASS", messages, data=data)
        if "status=queued" in messages or "status=in_progress" in messages or "no run for exact HEAD" in messages:
            return GateResult("PENDING", messages, data=data)
        if data.get("verdict") == "FAIL":
            return GateResult("FAIL", messages or "canonical pr-ready reported FAIL", data=data)
        return GateResult("BLOCKED_EXTERNAL", "canonical pr-ready returned contradictory or invalid check evidence", data=data)

    def merge_ready(self, *, worktree: str, base: str, head: str, mission_id: str,
                    scope_file: str, pr_number: int, pr_repo: str, pr_base_sha: str,
                    receipts: dict[str, str], ci_status: str, use_project_policy: bool = False) -> GateResult:
        """Delegate the final merge-readiness decision to the target project."""
        codex_receipt = receipts.get("codex")
        deepseek_receipt = receipts.get("deepseek")
        if not codex_receipt and not deepseek_receipt:
            return GateResult("BLOCKED_EXTERNAL", "canonical merge-readiness requires a durable review receipt")
        pr_state = self._pr_state(worktree, pr_number, pr_repo)
        if pr_state.status != "PASS":
            return pr_state
        pr_facts = pr_state.data if isinstance(pr_state.data, dict) else {}
        if (pr_facts.get("head") != head.lower() or pr_facts.get("base") != "main"
                or pr_facts.get("state") != "OPEN"
                or pr_facts.get("base_sha") != pr_base_sha.lower()):
            return GateResult("BLOCKED_EXTERNAL", "PR identity/base no longer matches exact reviewed approval")
        body = (pr_state.data or {}).get("body") if isinstance(pr_state.data, dict) else None
        if not isinstance(body, str):
            return GateResult("BLOCKED_EXTERNAL", "canonical merge-readiness requires the PR body")
        try:
            mission_id = self._safe_mission_id(mission_id)
        except ValueError as exc:
            return GateResult("BLOCKED_EXTERNAL", str(exc))
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-fA-F]{40}", head) is None:
            return GateResult("BLOCKED_EXTERNAL", "merge HEAD is not a full commit SHA")
        worktree_root = Path(worktree).resolve(strict=True)
        evidence_root = worktree_root.parent / ".cmh-merge-evidence"
        try:
            evidence = self._private_dir(
                evidence_root / mission_id / head.lower(), private_root=evidence_root,
            )
            body_path = evidence / "pr-body.md"
            self._write_private_file(body_path, body)
        except (OSError, RuntimeError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot prepare private merge evidence: {exc}")
        scope = Path(scope_file).resolve()
        trusted = self._trusted_base_checkout(worktree, base)
        # Execute the canonical implementation from the trusted base; the
        # candidate worktree is data, never executable authority here.
        preflight_code = (
            "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "from scripts.devops import agent_workflow_preflight as p; "
            "from scripts.ops.helpers import git_change_helpers as h; "
            "root=Path(sys.argv[2]); p.ROOT=root; h.ROOT_HELPER=root; "
            "sys.argv=['agent-preflight','--pr-body-file',sys.argv[3],"
            "'--mission-scope-file',sys.argv[4],'--base-ref',sys.argv[5],"
            "'--head-ref',sys.argv[6],'--require-review','--json']; "
            "raise SystemExit(p.main())"
        )
        local = self._call(
            [sys.executable, "-I", "-B", "-c", preflight_code, str(trusted), worktree,
             str(body_path), str(scope), base, head], cwd=str(trusted),
            env={"GH_HOST": "github.com", "PYTHONDONTWRITEBYTECODE": "1",
                 "HOME": "/nonexistent", "PATH": os.defpath, "LANG": "C.UTF-8"},
            inherit_environment=False,
        )
        if local.returncode != 0:
            return GateResult("BLOCKED_EXTERNAL", local.stderr.strip() or "canonical agent-preflight failed")
        try:
            local_json = self._json_document_prefix(local.stdout)
        except json.JSONDecodeError as exc:
            return GateResult("BLOCKED_EXTERNAL", f"canonical agent-preflight returned invalid JSON: {exc}")
        local_path = evidence / "local-preflight.json"
        try:
            self._write_private_file(local_path, json.dumps(local_json, sort_keys=True))
        except (OSError, RuntimeError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot safely persist local merge evidence: {exc}")
        code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                "from scripts.devops import agent_workflow as m, agent_workflow_preflight as p, pr_ready_check as r; "
                "from scripts.ops import ai_workflow_gate as g; from scripts.ops.helpers import git_change_helpers as h; "
                "p.ROOT=r.ROOT=g.ROOT=Path(sys.argv[2]); h.ROOT_HELPER=Path(sys.argv[2]); "
                "sys.argv=['agent-workflow']+sys.argv[3:]; raise SystemExit(m.main())")
        argv = ["python3", "-I", "-B", "-c", code, str(trusted), worktree, "merge-ready",
                "--repo-root", worktree, "--base-sha", base, "--head-sha", head,
                "--mission-id", mission_id, "--mission-scope-file", str(scope),
                "--local-preflight-json", str(local_path)]
        if codex_receipt:
            argv += ["--receipt", codex_receipt]
        if deepseek_receipt:
            argv += ["--deepseek-receipt", deepseek_receipt]
        local_verdict = str(local_json.get("verdict", "")).strip().upper()
        # The trusted target command rechecks local safety and remote PR
        # governance itself.  Bind the local declarations to the exact-head
        # preflight result, and leave governance UNKNOWN here: this adapter's
        # PR identity lookup does not establish the target's governance rules.
        protected_invariants = "PASS" if local_verdict == "PASS" else "UNKNOWN"
        forbidden_side_effects = "NO" if local_verdict == "PASS" else "UNKNOWN"
        required_pr_governance = "UNKNOWN"
        if not use_project_policy:
            argv += ["--selected-backend", "codex" if codex_receipt else "deepseek"]
        argv += ["--pr", str(pr_number), "--remote-ci-status", ci_status,
                "--protected-invariants", protected_invariants,
                "--forbidden-side-effects", forbidden_side_effects,
                "--required-pr-governance", required_pr_governance, "--json"]
        result = self._call(argv, cwd=str(trusted), env={"GH_HOST": "github.com", "GH_REPO": pr_repo,
                                                        "PYTHONDONTWRITEBYTECODE": "1"})
        try:
            data = self._json_document_prefix(result.stdout)
        except json.JSONDecodeError:
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "canonical agent-merge-ready returned invalid JSON")
        if result.returncode == 0 and data.get("merge_ready") == "YES":
            return GateResult("PASS", "canonical agent-merge-ready passed", data=data)
        return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "canonical agent-merge-ready rejected merge", data=data)

    def _pr_state(self, worktree: str, pr_number: int, pr_repo: str) -> GateResult:
        try:
            raw = json.loads(self._run(self._gh("api", f"repos/{pr_repo}/pulls/{pr_number}"), cwd=worktree))
        except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot inspect durable PR identity: {exc}")
        if not isinstance(raw, dict):
            return GateResult("BLOCKED_EXTERNAL", "GitHub PR lookup returned a non-object JSON value")
        head, base = raw.get("head"), raw.get("base")
        number = raw.get("number")
        if (not isinstance(head, dict) or not isinstance(base, dict)
                or not isinstance(number, int) or isinstance(number, bool)
                or number != pr_number
                or re.fullmatch(r"[0-9a-fA-F]{40}", str(head.get("sha", ""))) is None
                or re.fullmatch(r"[0-9a-fA-F]{40}", str(base.get("sha", ""))) is None
                or not isinstance(base.get("ref"), str)):
            return GateResult("BLOCKED_EXTERNAL", "GitHub PR lookup returned malformed or mismatched identity")
        return GateResult("PASS", f"{pr_repo} PR #{pr_number}", data={"repo": pr_repo, "raw": raw,
            "head": str(head.get("sha", "")).lower(),
            "base": str(base.get("ref", "")),
            "base_sha": str(base.get("sha", "")).lower(),
            "state": str(raw.get("state", "")).upper(), "body": raw.get("body", "")})

    def merge(self, worktree: str, head: str, pr_number: int | None = None,
              pr_repo: str | None = None, pr_base_sha: str | None = None) -> GateResult:
        if pr_number is None or not pr_repo or not pr_base_sha:
            return GateResult("BLOCKED_EXTERNAL", "merge claim has no durable PR/base identity")
        before = self.merge_status(worktree, head, pr_number, pr_repo,
                                   pr_base_sha=pr_base_sha, allow_open_retry=True)
        if before.status != "NOT_STARTED": return before
        freshness = self._strict_base_freshness(worktree, pr_repo)
        if freshness.status != "PASS":
            return freshness
        result = self._call(self._gh("pr", "merge", str(pr_number), "--repo", pr_repo,
                             "--squash", "--match-head-commit", head), cwd=worktree)
        if result.returncode != 0: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "merge command failed")
        return self.merge_status(worktree, head, pr_number, pr_repo,
                                 pr_base_sha=pr_base_sha)

    def _strict_base_freshness(self, worktree: str, pr_repo: str) -> GateResult:
        """Require server enforcement that rejects a PR after its base moves."""
        result = self._call(self._gh(
            "api", f"repos/{pr_repo}/branches/main/protection"), cwd=worktree,
        )
        if result.returncode != 0:
            return GateResult(
                "BLOCKED_POLICY",
                "cannot prove GitHub enforces strict base freshness; branch protection lookup "
                f"failed with exit {result.returncode}",
            )
        try:
            protection = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError):
            return GateResult("BLOCKED_POLICY", "GitHub branch protection response is not valid JSON")
        if not isinstance(protection, dict):
            return GateResult("BLOCKED_POLICY", "GitHub branch protection response is malformed")
        statuses = protection.get("required_status_checks")
        if not isinstance(statuses, dict) or statuses.get("strict") is not True:
            return GateResult("BLOCKED_POLICY", "GitHub main branch does not require strict up-to-date checks")
        contexts = statuses.get("contexts", [])
        checks = statuses.get("checks", [])
        if (not isinstance(contexts, list) or not isinstance(checks, list)
                or not any(isinstance(item, str) and item for item in contexts)
                and not any(isinstance(item, dict) and isinstance(item.get("context"), str)
                            and item["context"] for item in checks)):
            return GateResult("BLOCKED_POLICY", "GitHub strict base protection has no required status checks")
        admins = protection.get("enforce_admins")
        if not isinstance(admins, dict) or admins.get("enabled") is not True:
            return GateResult("BLOCKED_POLICY", "GitHub strict base protection does not cover administrators")
        rules_result = self._call(self._gh(
            "api", f"repos/{pr_repo}/rules/branches/main"), cwd=worktree)
        if rules_result.returncode != 0:
            return GateResult("BLOCKED_POLICY", "cannot prove GitHub main has no merge queue rule")
        try:
            rules = json.loads(rules_result.stdout)
        except (TypeError, json.JSONDecodeError):
            return GateResult("BLOCKED_POLICY", "GitHub main branch rules response is invalid")
        if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
            return GateResult("BLOCKED_POLICY", "GitHub main branch rules response is malformed")
        if any(rule.get("type") == "merge_queue" for rule in rules):
            return GateResult("BLOCKED_POLICY", "GitHub main branch uses a merge queue")
        return GateResult("PASS", "GitHub enforces strict up-to-date checks for main and administrators")

    def merge_status(self, worktree: str, reviewed_head: str, pr_number: int | None = None,
                     pr_repo: str | None = None, pr_base_sha: str | None = None,
                     allow_open_retry: bool = False) -> GateResult:
        if pr_number is None or not pr_repo or not pr_base_sha:
            return GateResult("BLOCKED_EXTERNAL", "merge claim has no durable PR/base identity")
        try:
            data = json.loads(self._run(self._gh("api", f"repos/{pr_repo}/pulls/{pr_number}"), cwd=worktree))
        except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot reconcile merge state: {exc}")
        if not isinstance(data, dict):
            return GateResult("BLOCKED_EXTERNAL", "GitHub merge-status lookup returned a non-object JSON value")
        number, head, base = data.get("number"), data.get("head"), data.get("base")
        if (not isinstance(number, int) or isinstance(number, bool) or number != pr_number
                or not isinstance(head, dict) or not isinstance(base, dict)):
            return GateResult("BLOCKED_EXTERNAL", "GitHub merge-status lookup returned malformed or mismatched PR identity")
        if data.get("merged") is True:
            merged_head = str(head.get("sha", "")).lower()
            if merged_head != reviewed_head.lower():
                return GateResult("BLOCKED_EXTERNAL", f"merged PR head {merged_head or 'MISSING'} differs from reviewed head {reviewed_head}")
            if str(base.get("ref", "")) != "main":
                return GateResult("BLOCKED_EXTERNAL", "merged PR base differs from main")
            merge_sha = str(data.get("merge_commit_sha") or "").lower()
            if not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
                return GateResult("BLOCKED_EXTERNAL", "merged PR lacks a full merge SHA")
            try:
                commit = json.loads(self._run(self._gh("api", f"repos/{pr_repo}/commits/{merge_sha}"), cwd=worktree))
            except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
                return GateResult("BLOCKED_EXTERNAL", f"cannot validate merge base parent: {exc}")
            parents = commit.get("parents") if isinstance(commit, dict) else None
            first_parent = (parents[0].get("sha", "").lower()
                            if isinstance(parents, list) and parents and isinstance(parents[0], dict) else "")
            if first_parent != pr_base_sha.lower():
                return GateResult("BLOCKED_EXTERNAL", "merge commit first parent differs from approved PR base SHA")
            return GateResult("PASS", f"merged {pr_repo} PR #{pr_number}", data={
                "pr": pr_number, "merge_sha": merge_sha, "repo": pr_repo,
                "pr_base_sha": pr_base_sha.lower(),
            })
        queued = data.get("auto_merge") is not None or data.get("merge_queue_entry") is not None
        if (allow_open_retry and data.get("merged") is False and not queued
                and str(data.get("state", "")).upper() == "OPEN"
                and str(base.get("ref", "")) == "main"
                and str(base.get("sha", "")).lower() == pr_base_sha.lower()
                and str(head.get("sha", "")).lower() == reviewed_head.lower()):
            return GateResult("NOT_STARTED", f"PR #{pr_number} remains open at reviewed HEAD/base; merge retry is safe", data={
                "pr": pr_number, "repo": pr_repo, "pr_base_sha": pr_base_sha.lower(),
            })
        return GateResult("BLOCKED_EXTERNAL", f"ambiguous merge state for PR #{pr_number}")

    def post_merge(self, worktree: str, merge_sha: str, pr_number: int, pr_repo: str,
                   branch: str, base: str) -> GateResult:
        trusted = self._trusted_base_checkout(worktree, base)
        code = ("import sys; from pathlib import Path; "
                "sys.path.insert(0, str(Path(sys.argv[1]) / 'scripts/devops')); "
                "import pr_post_merge_check as m; "
                "sys.argv=['pr-post-merge-check']+sys.argv[2:]; raise SystemExit(m.main())")
        result = self._call([self._trusted_python_interpreter(), "-I", "-B", "-c", code, str(trusted),
                             "--pr", str(pr_number), "--merge-commit", merge_sha,
                             "--branch", branch, "--json"], cwd=worktree,
                            env={"GH_REPO": pr_repo, "GH_HOST": "github.com", "PYTHONDONTWRITEBYTECODE": "1"})
        try: data = self._json_document_prefix(result.stdout)
        except json.JSONDecodeError: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate check returned no JSON")
        if not isinstance(data, dict):
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate check returned no JSON")
        if str(data.get("ci_head_sha", "")).lower() != merge_sha.lower():
            return GateResult("BLOCKED_EXTERNAL", "Production Gate is not bound to exact merge SHA")
        if str(data.get("ci_status")) in {"queued", "in_progress", "requested"}:
            return GateResult("PENDING", json.dumps(data), data=data)
        if result.returncode != 0 and data.get("verdict") == "PASS":
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate exit status contradicts PASS", data=data)
        if result.returncode != 0 and data.get("verdict") != "FAIL":
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate command failed", data=data)
        if data.get("verdict") == "PASS":
            try:
                self._assert_safe_local_git_config(
                    worktree, self._trusted_subprocess_environment())
                if self._repo_from_origin(worktree) != pr_repo:
                    return GateResult("BLOCKED_EXTERNAL", "post-merge origin differs from the approved repository")
                self._run(["git", "fetch", "origin", "main"], cwd=worktree)
                # Capture the remote-tracking ref once, then derive every
                # related fact from that immutable full SHA.  A concurrent
                # fetch may advance origin/main between commands, but it can
                # no longer produce a mixed commit/tree observation.
                main_sha = self._run(["git", "rev-parse", "origin/main"], cwd=worktree).strip().lower()
                tree_sha = self._run(["git", "rev-parse", f"{main_sha}^{{tree}}"], cwd=worktree).strip().lower()
                reachable = self._call(["git", "merge-base", "--is-ancestor", merge_sha, main_sha], cwd=worktree)
            except (subprocess.SubprocessError, OSError) as exc:
                return GateResult("BLOCKED_EXTERNAL", f"cannot record post-merge main truth: {exc}")
            if reachable.returncode != 0:
                return GateResult("BLOCKED_EXTERNAL", "merged SHA is not reachable from origin/main")
            data.update({"main_sha": main_sha, "tree_sha": tree_sha})
            return GateResult("PASS", "canonical Production Gate passed", data=data)
        if not data.get("ci_status"): return GateResult("BLOCKED_EXTERNAL", "Production Gate omitted CI status", data=data)
        if data.get("verdict") == "FAIL": return GateResult("FAIL", json.dumps(data), data=data)
        return GateResult("BLOCKED_EXTERNAL", "Production Gate returned an invalid verdict", data=data)

    @classmethod
    def _call(cls, argv, cwd=None, env=None, inherit_environment=True):
        try:
            trusted_argv = cls._trusted_command_argv(argv)
            child_env = cls._trusted_subprocess_environment(
                env=env, inherit_environment=inherit_environment,
            )
            return subprocess.run(trusted_argv, cwd=cwd, env=child_env, text=True,
                                  capture_output=True, check=False, timeout=60)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return subprocess.CompletedProcess(argv, 124, stdout, f"command timed out after 60 seconds: {argv[0]}")
        except (OSError, RuntimeError, ValueError) as exc:
            return subprocess.CompletedProcess(argv, 127, "", f"cannot execute command: {exc}")

    @classmethod
    def _run(cls, argv, cwd=None):
        try:
            trusted_argv = cls._trusted_command_argv(argv)
            child_env = cls._trusted_subprocess_environment(inherit_environment=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise subprocess.SubprocessError(f"cannot prepare trusted command: {exc}") from exc
        return subprocess.check_output(trusted_argv, cwd=cwd, env=child_env, text=True,
                                       stderr=subprocess.PIPE, timeout=60)
    @staticmethod
    def _json_last_line(path):
        try:
            for line in reversed(Path(path).read_text(encoding="utf-8").splitlines()):
                try: value = json.loads(line)
                except json.JSONDecodeError: continue
                if isinstance(value, dict): return value
        except OSError: pass
        return {}

    @staticmethod
    def _json_last_text(text: str) -> dict[str, Any]:
        for line in reversed(text.splitlines()):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
        return {}

    @staticmethod
    def _json_document_prefix(text: str) -> dict[str, Any]:
        """Read the first JSON document while ignoring canonical human footer text."""
        decoder = json.JSONDecoder()
        value, _ = decoder.raw_decode(text.lstrip())
        if not isinstance(value, dict):
            raise json.JSONDecodeError("expected JSON object", text, 0)
        return value


class SimulatedAdapter(FootballPredictionAdapter):
    """Deterministic non-production adapter used only by tests and the safe demonstration."""
    def __init__(self, heads=None, reviews=None, ci=None, merge=None, post_merge=None):
        self.heads, self.reviews, self.ci_results = heads or ["a" * 40], reviews or ["PASS", "PASS"], ci or ["PASS"]
        self.merge_results, self.post_results = merge or ["PASS"], post_merge or ["PASS"]
        self.head_index = self.review_index = self.ci_index = self.merge_index = self.post_index = 0
        self.merged_heads: set[str] = set()
    def exact_head(self, worktree): return self.heads[min(self.head_index, len(self.heads)-1)]
    def gate_argv(self, gate): return ["/bin/sh", "-c", "exit 0"]
    def discover_pr(self, worktree, head): return GateResult("PASS", "fixture PR", data={
        "number": 1, "repo": "fixture/repo", "base_sha": "b" * 40,
    })
    def review_argv(self, *args, **kwargs): return ["/bin/sh", "-c", "exit 0"]
    def review(self, reviewer, head):
        value=self.reviews[min(self.review_index,len(self.reviews)-1)]; self.review_index+=1; return GateResult(value, f"fixture {reviewer}", "/tmp/fake")
    def review_result(self, reviewer, **kwargs):
        value=self.reviews[min(self.review_index,len(self.reviews)-1)]; self.review_index+=1; return GateResult(value, f"fixture {reviewer}", "/tmp/fake")
    def ci(self, worktree, head, pr_number=None, pr_repo=None, base_sha=None, pr_base_sha=None):
        value=self.ci_results[min(self.ci_index,len(self.ci_results)-1)]; self.ci_index+=1
        return GateResult(value, f"fixture CI {head}", data={
            "pr_number": pr_number or 1, "pr_repo": pr_repo or "fixture/repo",
            "pr_base_sha": pr_base_sha or base_sha or ("b" * 40),
        })
    def merge_ready(self, **kwargs): return GateResult("PASS", "fixture merge readiness")
    def merge(self, worktree, head, pr_number=None, pr_repo=None, pr_base_sha=None):
        value = self.merge_results[min(self.merge_index, len(self.merge_results)-1)]
        self.merge_index += 1
        if value == "PASS":
            self.merged_heads.add(head)
            return GateResult(value, f"fixture merge {head}", data={
                "pr": pr_number or 1, "repo": pr_repo or "fixture/repo", "merge_sha": "c" * 40,
                "pr_base_sha": pr_base_sha,
            })
        return GateResult(value, f"fixture merge {head}")
    def merge_status(self, worktree, reviewed_head, pr_number=None, pr_repo=None, pr_base_sha=None):
        if reviewed_head in self.merged_heads:
            return GateResult("PASS", f"fixture merge status {reviewed_head}", data={
                "pr": pr_number or 1, "repo": pr_repo or "fixture/repo", "merge_sha": "c" * 40,
                "pr_base_sha": pr_base_sha,
            })
        return GateResult("NOT_STARTED", f"fixture merge status {reviewed_head}")
    def post_merge(self, *args):
        value=self.post_results[min(self.post_index,len(self.post_results)-1)]; self.post_index+=1
        return GateResult(value, "fixture post merge", data={"main_sha":"d"*40,"tree_sha":"e"*40})

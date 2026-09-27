from __future__ import annotations

import json
import os
import queue
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .policy import SENSITIVE


@dataclass(frozen=True)
class Turn:
    thread_id: str
    turn_id: str
    text: str


class CodexAdapter(Protocol):
    def start_or_resume(self, thread_id: str | None, cwd: str) -> str: ...
    def turn(self, thread_id: str, prompt: str, cwd: str) -> Turn: ...


class AppServerCodex:
    """Thin JSON-RPC adapter for the locally installed App Server; protocol stays here."""
    MODEL = "gpt-5.6-sol"
    REASONING_EFFORT = "high"
    RESPONSE_TIMEOUT_SECONDS = 300.0
    MAX_PENDING_MESSAGES = 256

    def __init__(self, executable: str = "codex", *,
                 forbidden_actions: tuple[str, ...] = (), worktree: str | None = None):
        # Both the mission deny-list and its validated worktree are immutable
        # constructor inputs. A later caller may verify them, but may not bind
        # either authority boundary from turn-supplied data.
        if worktree is None:
            raise ValueError("Codex mission worktree must be constructor-bound")
        self._forbidden_actions = self._effective_policy(forbidden_actions)
        self._configured_forbidden_actions = self._effective_policy(forbidden_actions)
        self._policy_cwd = self._canonical_worktree(worktree)
        self.proc = subprocess.Popen([executable, "-c", f'model="{self.MODEL}"',
                                      "-c", f'model_reasoning_effort="{self.REASONING_EFFORT}"',
                                      "app-server", "--stdio"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1,
                                     env=self._app_server_environment(executable, self._policy_cwd))
        self.seq = 0
        self._pending_messages: list[dict] = []
        self._reader_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._reader_thread: threading.Thread | None = None
        try:
            self._request("initialize", {
                "clientInfo": {"name": "codex-mission-harness", "version": "0.1"},
            })
        except Exception:
            self.close()
            raise

    @staticmethod
    def _trusted_executable(executable: str, forbidden_root: str | None = None) -> Path:
        """Resolve a launcher only when its file and path are trusted.

        The launcher runs before the App Server sandbox exists, with the
        authenticated ``CODEX_HOME`` in its environment.  A path supplied by
        a mission therefore must never select a candidate-controlled file.
        Keep the lexical path check as well as the resolved target check so a
        symlink placed in the mission worktree cannot escape this boundary.
        """
        resolved_name = shutil.which(executable, path=os.environ.get("PATH", os.defpath))
        if not resolved_name:
            raise RuntimeError("trusted Codex App Server launcher is unavailable")
        try:
            lexical = Path(resolved_name).absolute()
            target = lexical.resolve(strict=True)
            root = Path(forbidden_root).resolve(strict=True) if forbidden_root else None
        except (OSError, RuntimeError) as exc:
            raise RuntimeError("trusted Codex App Server launcher is unavailable") from exc
        for candidate in (lexical, target):
            if root is not None:
                try:
                    candidate.relative_to(root)
                except ValueError:
                    pass
                else:
                    raise RuntimeError("Codex App Server launcher cannot be inside the mission worktree")

        owners = {0, os.getuid()} if hasattr(os, "getuid") else {0}
        for ancestor in (lexical.parent, *lexical.parent.parents):
            try:
                source = ancestor.lstat()
            except OSError as exc:
                raise RuntimeError("trusted Codex App Server launcher is unavailable") from exc
            source_mode = stat.S_IMODE(source.st_mode)
            private_group_write = (source.st_gid == source.st_uid
                                   and source_mode & 0o020
                                   and not source_mode & 0o002)
            if (not stat.S_ISDIR(source.st_mode) or source.st_uid not in owners
                    or (source_mode & 0o022 and not private_group_write)):
                raise RuntimeError("trusted Codex App Server launcher is not owner-controlled")
        try:
            info = target.lstat()
        except OSError as exc:
            raise RuntimeError("trusted Codex App Server launcher is unavailable") from exc
        # A user-owned npm launcher is commonly group-writable by the user's
        # private primary group.  Allow that case, while rejecting writes by a
        # different group or by others.
        group_write_is_private = info.st_gid == info.st_uid
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners
                or not (stat.S_IMODE(info.st_mode) & 0o111)
                or stat.S_IMODE(info.st_mode) & 0o002
                or (stat.S_IMODE(info.st_mode) & 0o020 and not group_write_is_private)):
            raise RuntimeError("trusted Codex App Server launcher is not owner-controlled")

        for ancestor in (target.parent, *target.parent.parents):
            try:
                directory = ancestor.lstat()
            except OSError as exc:
                raise RuntimeError("trusted Codex App Server launcher is unavailable") from exc
            directory_mode = stat.S_IMODE(directory.st_mode)
            private_group_write = (directory.st_gid == directory.st_uid
                                   and directory_mode & 0o020
                                   and not directory_mode & 0o002)
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid not in owners
                    or (directory_mode & 0o022 and not private_group_write)):
                raise RuntimeError("trusted Codex App Server launcher is not owner-controlled")
        return target

    @staticmethod
    def _trusted_environment_path(executable: str, forbidden_root: str | None = None) -> str:
        """Return a PATH made only from owner-controlled executable directories.

        The App Server is a controller child, so it must not inherit a caller
        PATH that can select repository-controlled launchers.  Keep the
        resolved executable's directory when it is trusted, then add the
        standard system directories needed by Codex's child tools.
        """
        owners = {0, os.getuid()} if hasattr(os, "getuid") else {0}
        candidates: list[Path] = []
        candidates.append(AppServerCodex._trusted_executable(executable, forbidden_root).parent)
        candidates.extend(Path(entry) for entry in (
            "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
            "/sbin", "/bin",
        ))
        trusted: list[str] = []
        for directory in candidates:
            try:
                resolved = directory.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_dir() or str(resolved) in trusted:
                continue
            if forbidden_root is not None:
                try:
                    resolved.relative_to(Path(forbidden_root).resolve(strict=True))
                except ValueError:
                    pass
                else:
                    continue
            safe = True
            for ancestor in (resolved, *resolved.parents):
                try:
                    info = ancestor.stat()
                except OSError:
                    safe = False
                    break
                directory_mode = stat.S_IMODE(info.st_mode)
                private_group_write = (info.st_gid == info.st_uid
                                       and directory_mode & 0o020
                                       and not directory_mode & 0o002)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                        or (directory_mode & 0o022 and not private_group_write)):
                    safe = False
                    break
            if safe:
                trusted.append(str(resolved))
        if not trusted:
            raise RuntimeError("trusted Codex App Server PATH is unavailable")
        return os.pathsep.join(trusted)

    @staticmethod
    def _codex_home() -> str:
        """Select the authenticated Codex home without inheriting a broad HOME."""
        raw = os.environ.get("CODEX_HOME")
        if raw:
            candidate = Path(raw)
            if not candidate.is_absolute():
                raise RuntimeError("CODEX_HOME must be an absolute path")
        else:
            candidate = Path.home() / ".codex"
        try:
            lexical = candidate.absolute()
            resolved = lexical.resolve(strict=True)
            if lexical != resolved:
                raise RuntimeError("Codex authentication home must not contain symlinks")
            uid = os.getuid() if hasattr(os, "getuid") else resolved.lstat().st_uid
            owners = {0, uid}
            parts = lexical.parts
            current = Path(parts[0])
            for index, component in enumerate(parts):
                if index == 0:
                    current = Path(component)
                else:
                    current /= component
                info = current.lstat()
                mode = stat.S_IMODE(info.st_mode)
                ancestor = index < len(parts) - 1
                sticky_shared = ancestor and bool(info.st_mode & stat.S_ISVTX) and bool(mode & 0o022)
                if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid not in (owners if ancestor else {uid})
                        or (mode & 0o022 and not sticky_shared)):
                    raise RuntimeError("Codex authentication home is not owner-controlled")
        except OSError as exc:
            raise RuntimeError("Codex authentication home is unavailable") from exc
        except RuntimeError:
            raise
        return str(resolved)

    @classmethod
    def _app_server_environment(cls, executable: str, forbidden_root: str | None = None) -> dict[str, str]:
        """Build the App Server's explicit environment allowlist.

        Authentication is carried by the deliberately selected ``CODEX_HOME``
        directory.  Proxy and CA settings are retained for the service request,
        while controller credentials, SSH agents, and arbitrary execution
        controls are excluded from the child environment.
        """
        code_home = cls._codex_home()
        environment = {
            "PATH": cls._trusted_environment_path(executable, forbidden_root),
            "HOME": "/nonexistent",
            "CODEX_HOME": code_home,
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "NO_COLOR": "1",
        }
        for name in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        ):
            value = os.environ.get(name)
            if value:
                environment[name] = value
        # These variables point at system-managed CA material rather than
        # carrying credentials.  Ignore non-absolute or user-writable paths.
        for name in (
            "CODEX_CA_CERTIFICATE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
            "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE",
        ):
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
                expected = stat.S_ISDIR(info.st_mode) if name == "SSL_CERT_DIR" else stat.S_ISREG(info.st_mode)
                if (not path.is_absolute() or stat.S_ISLNK(info.st_mode)
                        or not expected or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
                    safe = False
                    break
            if safe:
                environment[name] = value
        return environment

    def set_policy(self, forbidden_actions: tuple[str, ...], cwd: str) -> None:
        """Verify constructor-bound mission controls before a turn is started.

        App Server's workspace-write sandbox is restricted to the mission
        worktree and has no network access whenever the mission carries a
        deny-list.  Approval requests are deliberately not auto-approved by
        this adapter, so an attempted forbidden escape fails closed.
        """
        requested = self._effective_policy(forbidden_actions)
        configured = getattr(self, "_configured_forbidden_actions", None)
        if configured is None or requested != configured:
            raise RuntimeError("Codex policy differs from the configured mission deny-list")
        if "source_edit" in requested:
            raise PermissionError("mission forbids delegated source editing")
        bound = getattr(self, "_policy_cwd", None)
        if bound is None:
            raise RuntimeError("Codex mission worktree was not constructor-bound")
        canonical = self._canonical_worktree(cwd)
        if bound != canonical:
            raise RuntimeError("Codex mission worktree policy is immutable after first binding")
        self._forbidden_actions = requested

    @staticmethod
    def _canonical_worktree(cwd: str) -> str:
        candidate = Path(cwd)
        if not candidate.is_absolute():
            raise RuntimeError("Codex mission worktree must be an absolute canonical path")
        try:
            canonical = candidate.resolve(strict=True)
            top = Path(subprocess.check_output(
                ["git", "-C", str(canonical), "rev-parse", "--show-toplevel"],
                text=True, stderr=subprocess.DEVNULL,
            ).strip()).resolve(strict=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("Codex policy path is not a valid Git worktree") from exc
        if not canonical.is_dir() or str(canonical) != cwd or top != canonical:
            raise RuntimeError("Codex mission worktree must be its canonical Git top-level path")
        return str(canonical)

    @staticmethod
    def _effective_policy(forbidden_actions: tuple[str, ...]) -> tuple[str, ...]:
        """Always apply the sensitive-action baseline, even for an omitted deny-list."""
        return tuple(sorted(set(forbidden_actions) | set(SENSITIVE)))

    def _policy_params(self, cwd: str) -> dict:
        if not self._forbidden_actions:
            raise RuntimeError("Codex sandbox policy is missing its sensitive-action baseline")
        root = getattr(self, "_policy_cwd", None)
        if root is None:
            raise RuntimeError("Codex sandbox policy is not bound to a mission worktree")
        if cwd != root:
            raise RuntimeError("Codex caller cwd differs from the bound mission worktree")
        return {
            "approvalPolicy": "never",
            "sandboxPolicy": {
                "type": "workspaceWrite",
                "writableRoots": [root],
                "networkAccess": False,
            },
        }

    def _thread_policy_params(self, cwd: str) -> dict:
        """Express the turn sandbox equivalently in thread start/resume schema."""
        policy = self._policy_params(cwd)
        root = policy["sandboxPolicy"]["writableRoots"][0]
        return {
            "cwd": root,
            "model": self.MODEL,
            "approvalPolicy": policy["approvalPolicy"],
            "sandbox": "workspace-write",
            "developerInstructions": self._authority_instructions(root),
            "config": {
                "sandbox_workspace_write": {
                    "writable_roots": [root],
                    "network_access": False,
                },
                # The App Server needs CODEX_HOME to authenticate, but its
                # delegated shell commands must not inherit the path to that
                # credential directory. This is an enforced subprocess
                # environment filter, not an instruction to the model.
                "shell_environment_policy": {
                    "filters": {"CODEX_HOME": "exclude"},
                    "ignore_default_excludes": False,
                },
            },
        }

    def _authority_instructions(self, root: str) -> str:
        denied = ", ".join(self._forbidden_actions)
        return (
            f"Mission authority boundary: only source editing inside {root} is delegated. "
            f"Controller-only forbidden actions are: {denied}. Never perform, request, or "
            "simulate merge or another forbidden/sensitive action. If one is required, stop "
            "and report the boundary; App Server approval requests are always denied."
        )

    def _deadline(self) -> float:
        timeout = float(getattr(self, "_response_timeout", self.RESPONSE_TIMEOUT_SECONDS))
        if timeout <= 0:
            raise RuntimeError("Codex App Server response timeout must be positive")
        return time.monotonic() + timeout

    def _ensure_reader(self) -> None:
        if getattr(self, "_reader_thread", None) is not None:
            return
        assert self.proc.stdout
        if getattr(self, "_reader_queue", None) is None:
            self._reader_queue = queue.Queue()

        def read_lines() -> None:
            try:
                while True:
                    line = self.proc.stdout.readline()
                    self._reader_queue.put(("line", line))
                    if line == "":
                        return
            except BaseException as exc:
                self._reader_queue.put(("error", exc))

        self._reader_thread = threading.Thread(
            target=read_lines, name="codex-app-server-stdout", daemon=True,
        )
        self._reader_thread.start()

    def _read_message(self, deadline: float | None = None) -> dict:
        """Read one JSON-RPC message and fail closed on EOF/protocol damage."""
        assert self.proc.stdout
        self._ensure_reader()
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.close()
                raise RuntimeError("Codex App Server response deadline exceeded")
        else:
            remaining = None
        try:
            kind, payload = self._reader_queue.get(timeout=remaining)
        except queue.Empty:
            self.close()
            raise RuntimeError("Codex App Server response deadline exceeded") from None
        if kind == "error":
            self.close()
            raise RuntimeError("Codex App Server stdout reader failed") from payload
        line = payload
        if not isinstance(line, str):
            self.close()
            raise RuntimeError("Codex App Server stdout reader returned non-text data")
        if line == "":
            self.close()
            raise RuntimeError("Codex App Server exited before sending a response")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            self.close()
            raise RuntimeError("Codex App Server emitted malformed JSON") from exc
        if not isinstance(message, dict):
            self.close()
            raise RuntimeError("Codex App Server emitted a non-object message")
        return message

    def close(self) -> None:
        """Idempotently release the App Server process and its stdio pipes."""
        if getattr(self, "_closed", False):
            return
        self._closed = True
        proc = getattr(self, "proc", None)
        if proc is None:
            return
        poll = getattr(proc, "poll", None)
        try:
            if callable(poll) and poll() is None:
                terminate = getattr(proc, "terminate", None)
                if callable(terminate):
                    try:
                        terminate()
                    except OSError:
                        pass
                wait = getattr(proc, "wait", None)
                if callable(wait):
                    try:
                        wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        kill = getattr(proc, "kill", None)
                        if callable(kill):
                            try:
                                kill()
                            except OSError:
                                pass
                        try:
                            wait(timeout=5)
                        except (OSError, subprocess.TimeoutExpired):
                            pass
        finally:
            for stream_name in ("stdin", "stdout", "stderr"):
                stream = getattr(proc, stream_name, None)
                close = getattr(stream, "close", None)
                if callable(close):
                    try:
                        close()
                    except OSError:
                        pass

    def _pending(self) -> list[dict]:
        pending = getattr(self, "_pending_messages", None)
        if pending is None:
            pending = []
            self._pending_messages = pending
        return pending

    def _take_pending(self, predicate) -> dict | None:
        pending = self._pending()
        for index, message in enumerate(pending):
            if predicate(message):
                return pending.pop(index)
        return None

    def _stash(self, message: dict) -> None:
        # Progress/item notifications have no future synchronous consumer. Keep
        # only out-of-order responses and turn completions that another wait
        # can still match.
        if "id" not in message and message.get("method") != "turn/completed":
            return
        pending = self._pending()
        if len(pending) >= self.MAX_PENDING_MESSAGES:
            raise RuntimeError("Codex App Server pending message limit exceeded")
        pending.append(message)

    def _reject_server_request(self, message: dict) -> bool:
        """Reject unsolicited approval/tool requests instead of hanging forever."""
        if "method" not in message or "id" not in message:
            return False
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps({
            "id": message["id"],
            "error": {"code": -32001, "message": "request denied by mission harness policy"},
        }) + "\n")
        self.proc.stdin.flush()
        return True

    def _request(self, method: str, params: dict) -> dict:
        self.seq += 1
        request_id = self.seq
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps({"id": request_id, "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        deadline = self._deadline()
        while True:
            message = self._take_pending(lambda item: item.get("id") == request_id)
            if message is None:
                message = self._read_message(deadline)
            if self._reject_server_request(message):
                continue
            if message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message["result"]
            self._stash(message)

    def _turn_completed(self, thread_id: str, turn_id: str) -> dict:
        """Wait for the App Server completion notification; acceptance is never turn completion."""
        assert self.proc.stdout
        deadline = self._deadline()

        def matches(message: dict) -> bool:
            params = message.get("params", {})
            if not isinstance(params, dict):
                return False
            turn = params.get("turn", {})
            if not isinstance(turn, dict):
                return False
            return (message.get("method") == "turn/completed" and
                    params.get("threadId") == thread_id and turn.get("id") == turn_id)

        while True:
            message = self._take_pending(matches)
            if message is None:
                message = self._read_message(deadline)
            if self._reject_server_request(message):
                continue
            if not matches(message):
                self._stash(message)
                continue
            params = message.get("params", {})
            turn = params.get("turn", {})
            if turn.get("status") != "completed":
                raise RuntimeError(f"Codex turn failed: {turn.get('error')}")
            return turn

    def start_or_resume(self, thread_id: str | None, cwd: str) -> str:
        policy = self._thread_policy_params(cwd)
        if thread_id:
            params = {"threadId": thread_id}
            params.update(policy)
            result = self._request("thread/resume", params)
        else:
            params = dict(policy)
            result = self._request("thread/start", params)
        return result["thread"]["id"]

    def turn(self, thread_id: str, prompt: str, cwd: str) -> Turn:
        params = {"threadId": thread_id, "input": [{"type": "text", "text": prompt}],
                  "cwd": cwd, "model": self.MODEL, "effort": self.REASONING_EFFORT}
        params.update(self._policy_params(cwd))
        result = self._request("turn/start", params)
        turn_id = result["turn"]["id"]
        completed = self._turn_completed(thread_id, turn_id)
        text = ""
        for item in completed.get("items", []):
            if item.get("type") == "agentMessage":
                text += item.get("text", "")
        return Turn(thread_id, turn_id, text)


class FixtureCodex:
    """Deterministic Codex contract for explicitly simulation-only missions."""
    def __init__(self):
        self.turns = 0
        self.policy: tuple[str, ...] = ()

    def set_policy(self, forbidden_actions: tuple[str, ...], cwd: str) -> None:
        self.policy = tuple(sorted(set(forbidden_actions) | set(SENSITIVE)))
    def start_or_resume(self, thread_id: str | None, cwd: str) -> str:
        return thread_id or "fixture-thread"
    def turn(self, thread_id: str, prompt: str, cwd: str) -> Turn:
        self.turns += 1
        return Turn(thread_id, f"fixture-turn-{self.turns}", "任务尚未完成。")

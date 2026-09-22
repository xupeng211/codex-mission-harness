from __future__ import annotations

import json
import queue
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
        self.proc = subprocess.Popen([executable, "app-server", "--stdio"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1)
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
            "approvalPolicy": policy["approvalPolicy"],
            "sandbox": "workspace-write",
            "developerInstructions": self._authority_instructions(root),
            "config": {
                "sandbox_workspace_write": {
                    "writable_roots": [root],
                    "network_access": False,
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
        params = {"threadId": thread_id, "input": [{"type": "text", "text": prompt}], "cwd": cwd}
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

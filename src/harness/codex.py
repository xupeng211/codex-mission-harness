from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Protocol


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
    def __init__(self, executable: str = "codex", *,
                 forbidden_actions: tuple[str, ...] = ()):
        # The mission deny-list is injected before the real App Server is
        # constructed.  A later turn may bind the worktree, but it may not
        # replace the policy selected by the persisted mission contract.
        self._forbidden_actions = tuple(forbidden_actions)
        self._configured_forbidden_actions = tuple(forbidden_actions)
        self._policy_cwd: str | None = None
        self.proc = subprocess.Popen([executable, "app-server", "--stdio"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1)
        self.seq = 0
        self._request("initialize", {"clientInfo": {"name": "codex-mission-harness", "version": "0.1"}})

    def set_policy(self, forbidden_actions: tuple[str, ...], cwd: str) -> None:
        """Apply mission deny-list controls before a turn is started.

        App Server's workspace-write sandbox is restricted to the mission
        worktree and has no network access whenever the mission carries a
        deny-list.  Approval requests are deliberately not auto-approved by
        this adapter, so an attempted forbidden escape fails closed.
        """
        requested = tuple(forbidden_actions)
        configured = getattr(self, "_configured_forbidden_actions", requested)
        if requested != configured:
            raise RuntimeError("Codex policy differs from the configured mission deny-list")
        self._forbidden_actions = requested
        self._policy_cwd = cwd

    def _policy_params(self, cwd: str) -> dict:
        if not self._forbidden_actions:
            return {}
        root = self._policy_cwd or cwd
        return {
            "approvalPolicy": "on-request",
            "sandboxPolicy": {
                "type": "workspaceWrite",
                "writableRoots": [root],
                "networkAccess": False,
            },
        }

    def _read_message(self) -> dict:
        """Read one JSON-RPC message and fail closed on EOF/protocol damage."""
        assert self.proc.stdout
        line = self.proc.stdout.readline()
        if line == "":
            raise RuntimeError("Codex App Server exited before sending a response")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Codex App Server emitted malformed JSON") from exc
        if not isinstance(message, dict):
            raise RuntimeError("Codex App Server emitted a non-object message")
        return message

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
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps({"id": self.seq, "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        while True:
            message = self._read_message()
            if self._reject_server_request(message):
                continue
            if message.get("id") == self.seq:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message["result"]

    def _turn_completed(self, thread_id: str, turn_id: str) -> dict:
        """Wait for the App Server completion notification; acceptance is never turn completion."""
        assert self.proc.stdout
        while True:
            message = self._read_message()
            if self._reject_server_request(message):
                continue
            if message.get("method") != "turn/completed":
                continue
            params = message.get("params", {})
            turn = params.get("turn", {})
            if params.get("threadId") == thread_id and turn.get("id") == turn_id:
                if turn.get("status") != "completed":
                    raise RuntimeError(f"Codex turn failed: {turn.get('error')}")
                return turn

    def start_or_resume(self, thread_id: str | None, cwd: str) -> str:
        if thread_id:
            params = {"threadId": thread_id}
            if self._forbidden_actions:
                params.update({"approvalPolicy": "on-request", "sandbox": "workspace-write"})
            result = self._request("thread/resume", params)
        else:
            params = {"cwd": cwd}
            if self._forbidden_actions:
                params.update({"approvalPolicy": "on-request", "sandbox": "workspace-write"})
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
        return Turn(thread_id, turn_id, text or "turn completed")


class FixtureCodex:
    """Deterministic Codex contract for explicitly simulation-only missions."""
    def __init__(self):
        self.turns = 0
        self.policy: tuple[str, ...] = ()

    def set_policy(self, forbidden_actions: tuple[str, ...], cwd: str) -> None:
        self.policy = tuple(forbidden_actions)
    def start_or_resume(self, thread_id: str | None, cwd: str) -> str:
        return thread_id or "fixture-thread"
    def turn(self, thread_id: str, prompt: str, cwd: str) -> Turn:
        self.turns += 1
        return Turn(thread_id, f"fixture-turn-{self.turns}", "任务尚未完成。")

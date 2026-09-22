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
    def __init__(self, executable: str = "codex"):
        self.proc = subprocess.Popen([executable, "app-server", "--stdio"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1)
        self.seq = 0
        self._request("initialize", {"clientInfo": {"name": "codex-mission-harness", "version": "0.1"}})

    def _request(self, method: str, params: dict) -> dict:
        self.seq += 1
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps({"id": self.seq, "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        while True:
            message = json.loads(self.proc.stdout.readline())
            if message.get("id") == self.seq:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message["result"]

    def start_or_resume(self, thread_id: str | None, cwd: str) -> str:
        if thread_id:
            result = self._request("thread/resume", {"threadId": thread_id})
        else:
            result = self._request("thread/start", {"cwd": cwd})
        return result["thread"]["id"]

    def turn(self, thread_id: str, prompt: str, cwd: str) -> Turn:
        result = self._request("turn/start", {"threadId": thread_id, "input": [{"type": "text", "text": prompt}], "cwd": cwd})
        return Turn(thread_id, result["turn"]["id"], "turn accepted")

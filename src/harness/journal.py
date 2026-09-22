from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .domain import InvalidTransition, MissionSpec, Observation, State, TERMINAL, ALLOWED


def now() -> str:
    return datetime.now(UTC).isoformat()


class Journal:
    """SQLite is a journal/cache: Git, GitHub and project gates remain canonical truth."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(
            """
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS missions (
              mission_id TEXT PRIMARY KEY, spec_json TEXT NOT NULL, repo TEXT NOT NULL,
              base_sha TEXT, branch TEXT, worktree TEXT, current_head TEXT, codex_thread_id TEXT,
              current_state TEXT NOT NULL, pending_gate TEXT, completed_gates_json TEXT NOT NULL DEFAULT '{}',
              ci_state TEXT, approval_state TEXT NOT NULL DEFAULT 'NONE', terminal_state TEXT,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, kind TEXT NOT NULL,
              payload_json TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(mission_id) REFERENCES missions(mission_id));
            CREATE TABLE IF NOT EXISTS jobs (
              job_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, name TEXT NOT NULL, argv_json TEXT NOT NULL,
              launch_head TEXT, pid INTEGER, pgid INTEGER, start_ticks TEXT, state TEXT NOT NULL, exit_code INTEGER,
              stdout_path TEXT, stderr_path TEXT, started_at TEXT NOT NULL, ended_at TEXT);
            CREATE TABLE IF NOT EXISTS receipts (
              id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, reviewer TEXT NOT NULL,
              head_sha TEXT NOT NULL, result TEXT NOT NULL, artifact_path TEXT, invalidated INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS approvals (
              id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, action TEXT NOT NULL,
              decision TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_job_per_gate
              ON jobs(mission_id,name) WHERE state IN ('STARTING','RUNNING');
            """
        )
        self.db.commit()

    def create(self, spec: MissionSpec) -> None:
        stamp = now()
        self.db.execute(
            "INSERT INTO missions(mission_id,spec_json,repo,current_state,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (spec.mission_id, json.dumps(spec.__dict__), spec.repository, State.CREATED, stamp, stamp),
        )
        self.event(spec.mission_id, "mission_created", {"schema_version": spec.schema_version})
        self.db.commit()

    def event(self, mission_id: str, kind: str, payload: dict[str, Any]) -> None:
        self.db.execute("INSERT INTO events(mission_id,kind,payload_json,created_at) VALUES(?,?,?,?)",
                        (mission_id, kind, json.dumps(payload, sort_keys=True), now()))

    def mission(self, mission_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None:
            raise KeyError(mission_id)
        return row

    def transition(self, mission_id: str, target: State, reason: str) -> None:
        row = self.mission(mission_id)
        source = State(row["current_state"])
        if source in TERMINAL or target not in ALLOWED.get(source, set()):
            raise InvalidTransition(f"{source} -> {target} is forbidden")
        terminal = target if target in TERMINAL else None
        self.db.execute("UPDATE missions SET current_state=?,terminal_state=?,updated_at=? WHERE mission_id=?",
                        (target, terminal, now(), mission_id))
        self.event(mission_id, "state_transition", {"from": source, "to": target, "reason": reason})
        self.db.commit()

    def update(self, mission_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = now()
        keys = list(fields)
        self.db.execute("UPDATE missions SET " + ",".join(f"{k}=?" for k in keys) + " WHERE mission_id=?",
                        [fields[k] for k in keys] + [mission_id])
        self.db.commit()

    def complete_gate(self, mission_id: str, gate: str, head: str) -> None:
        row = self.mission(mission_id)
        gates = json.loads(row["completed_gates_json"])
        if isinstance(gates, list):  # v0.1 pre-release journal migration
            gates = {name: None for name in gates}
        gates[gate] = head
        self.update(mission_id, completed_gates_json=json.dumps(gates), pending_gate=None)
        self.event(mission_id, "gate_pass", {"gate": gate, "head": head})
        self.db.commit()

    def gate_passed_at_head(self, mission_id: str, gate: str, head: str) -> bool:
        gates = json.loads(self.mission(mission_id)["completed_gates_json"])
        return isinstance(gates, dict) and gates.get(gate) == head

    def record_receipt(self, mission_id: str, reviewer: str, head: str, result: str, artifact: str | None = None) -> None:
        self.db.execute("INSERT INTO receipts(mission_id,reviewer,head_sha,result,artifact_path,created_at) VALUES(?,?,?,?,?,?)",
                        (mission_id, reviewer, head, result, artifact, now()))
        self.event(mission_id, "review_result", {"reviewer": reviewer, "head": head, "result": result})
        self.db.commit()

    def invalidate_reviews(self, mission_id: str, current_head: str) -> int:
        result = self.db.execute("UPDATE receipts SET invalidated=1 WHERE mission_id=? AND head_sha<>? AND invalidated=0",
                                 (mission_id, current_head))
        if result.rowcount:
            self.event(mission_id, "reviews_invalidated", {"current_head": current_head, "count": result.rowcount})
            self.db.commit()
        return result.rowcount

    def valid_reviews(self, mission_id: str, head: str) -> set[str]:
        rows = self.db.execute("SELECT reviewer FROM receipts WHERE mission_id=? AND head_sha=? AND result='PASS' AND invalidated=0",
                               (mission_id, head)).fetchall()
        return {row[0] for row in rows}

    def status(self, mission_id: str) -> Observation:
        row = self.mission(mission_id)
        jobs = self.db.execute("SELECT count(*) FROM jobs WHERE mission_id=? AND state IN ('STARTING','RUNNING')", (mission_id,)).fetchone()[0]
        return Observation(State(row["current_state"]), row["current_head"], row["worktree"],
                           row["pending_gate"], jobs, row["terminal_state"] is not None)

from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .domain import InvalidTransition, MissionSpec, Observation, State, TERMINAL, ALLOWED
from .policy import Decision, SENSITIVE, decide


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
              merge_claim_head TEXT,
              merge_claim_pid INTEGER,
              merge_claim_start_ticks TEXT,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, kind TEXT NOT NULL,
              payload_json TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(mission_id) REFERENCES missions(mission_id));
            CREATE TABLE IF NOT EXISTS jobs (
              job_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, name TEXT NOT NULL, argv_json TEXT NOT NULL,
              launch_head TEXT, pid INTEGER, pgid INTEGER, start_ticks TEXT, state TEXT NOT NULL, exit_code INTEGER,
              stdout_path TEXT, stderr_path TEXT, started_at TEXT NOT NULL, ended_at TEXT,
              launcher_pid INTEGER, launcher_start_ticks TEXT, lease_token TEXT);
            CREATE TABLE IF NOT EXISTS receipts (
              id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, reviewer TEXT NOT NULL,
              head_sha TEXT NOT NULL, result TEXT NOT NULL, artifact_path TEXT, invalidated INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS approvals (
              id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, action TEXT NOT NULL,
              decision TEXT NOT NULL, reason TEXT, head_sha TEXT, spec_sha256 TEXT, created_at TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_job_per_gate
              ON jobs(mission_id,name) WHERE state IN ('STARTING','RUNNING');
            """
        )
        # Existing v0.1 journals are migrated in place; these fields make a STARTING
        # reservation recoverable without guessing from process names.
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(jobs)")}
        for name, definition in (("launcher_pid", "INTEGER"), ("launcher_start_ticks", "TEXT"), ("lease_token", "TEXT")):
            if name not in columns:
                self.db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")
        approval_columns = {row[1] for row in self.db.execute("PRAGMA table_info(approvals)")}
        if "head_sha" not in approval_columns:
            self.db.execute("ALTER TABLE approvals ADD COLUMN head_sha TEXT")
        if "spec_sha256" not in approval_columns:
            self.db.execute("ALTER TABLE approvals ADD COLUMN spec_sha256 TEXT")
        mission_columns = {row[1] for row in self.db.execute("PRAGMA table_info(missions)")}
        if "merge_claim_head" not in mission_columns:
            self.db.execute("ALTER TABLE missions ADD COLUMN merge_claim_head TEXT")
        for name, definition in (("merge_claim_pid", "INTEGER"), ("merge_claim_start_ticks", "TEXT")):
            if name not in mission_columns:
                self.db.execute(f"ALTER TABLE missions ADD COLUMN {name} {definition}")
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

    def spec(self, mission_id: str) -> MissionSpec:
        """Return the persisted mission contract; caller input is never authority."""
        row = self.mission(mission_id)
        try:
            value = json.loads(row["spec_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("persisted mission spec is invalid") from exc
        if not isinstance(value, dict):
            raise RuntimeError("persisted mission spec is invalid")
        try:
            spec = MissionSpec.from_mapping(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("persisted mission spec is invalid") from exc
        if spec.mission_id != mission_id or spec.repository != row["repo"]:
            raise RuntimeError("persisted mission identity does not match journal identity")
        return spec

    def _spec_digest(self, mission_id: str) -> str:
        # Validate before hashing so corrupt or schema-drifted contracts can
        # never authorize a sensitive action.
        self.spec(mission_id)
        payload = self.mission(mission_id)["spec_json"].encode()
        return hashlib.sha256(payload).hexdigest()

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

    def reconcile_head(self, mission_id: str, head: str) -> bool:
        """Atomically replace cached HEAD and revoke all downstream acceptance facts."""
        try:
            self.db.execute("BEGIN IMMEDIATE")
            # Read after the writer lock: another controller cannot race a stale
            # state decision into a later terminal acceptance.
            row = self.db.execute("SELECT current_head,current_state FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if row["current_head"] == head:
                self.db.commit()
                return False
            source = State(row["current_state"])
            self.db.execute("UPDATE missions SET current_head=?,updated_at=? WHERE mission_id=?", (head, now(), mission_id))
            invalidated = self.db.execute("UPDATE receipts SET invalidated=1 WHERE mission_id=? AND head_sha<>? AND invalidated=0",
                                          (mission_id, head)).rowcount
            if source == State.PASS:
                self.db.execute("UPDATE missions SET current_state=?,terminal_state=NULL,pending_gate=NULL,ci_state=NULL,approval_state='NONE',merge_claim_head=NULL,merge_claim_pid=NULL,merge_claim_start_ticks=NULL,updated_at=? WHERE mission_id=?",
                                (State.TEST, now(), mission_id))
                self.event(mission_id, "pass_reopened_for_new_head", {"reason": "canonical HEAD changed after PASS"})
            elif source in {State.REVIEW, State.CI, State.MERGE, State.WAITING_APPROVAL, State.POST_MERGE, State.DELIVER}:
                self.db.execute("UPDATE missions SET current_state=?,pending_gate=NULL,ci_state=NULL,approval_state='NONE',merge_claim_head=NULL,merge_claim_pid=NULL,merge_claim_start_ticks=NULL,updated_at=? WHERE mission_id=?",
                                (State.TEST, now(), mission_id))
                self.event(mission_id, "state_reconciled_to_test", {"from": source, "reason": "canonical HEAD changed"})
            self.event(mission_id, "canonical_head_reconciled", {"head": head, "invalidated_reviews": invalidated})
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return True

    def valid_reviews(self, mission_id: str, head: str) -> set[str]:
        rows = self.db.execute("SELECT reviewer FROM receipts WHERE mission_id=? AND head_sha=? AND result='PASS' AND invalidated=0",
                               (mission_id, head)).fetchall()
        return {row[0] for row in rows}

    def approve(self, mission_id: str, action: str, reason: str = "", observed_head: str | None = None) -> None:
        mission = self.mission(mission_id)  # fail closed for an unknown mission
        spec = self.spec(mission_id)
        if action not in SENSITIVE:
            raise ValueError(f"unknown or non-sensitive approval action: {action}")
        if action in spec.forbidden_actions:
            raise PermissionError(f"mission forbids action: {action}")
        if decide(action, spec.merge_policy) != Decision.OWNER_APPROVAL_REQUIRED:
            raise ValueError(f"mission policy does not require approval for action: {action}")
        head = mission["current_head"]
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-f]{40}", head) is None:
            raise RuntimeError("cannot approve before canonical HEAD reconciliation")
        if observed_head is not None and observed_head != head:
            raise RuntimeError("observed canonical HEAD differs from journal HEAD")
        if (State(mission["current_state"]) != State.WAITING_APPROVAL or
                mission["approval_state"] != "PENDING" or mission["pending_gate"] != f"owner-{action}"):
            raise RuntimeError(f"mission is not waiting for approval of action: {action}")
        spec_digest = self._spec_digest(mission_id)
        self.db.execute("INSERT INTO approvals(mission_id,action,decision,reason,head_sha,spec_sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                        (mission_id, action, "APPROVED", reason, head, spec_digest, now()))
        self.update(mission_id, approval_state="APPROVED")
        self.event(mission_id, "approval_granted", {"action": action, "head": head,
                                                      "spec_sha256": spec_digest, "reason": reason})
        self.db.commit()

    def approved(self, mission_id: str, action: str, head: str) -> bool:
        mission = self.mission(mission_id)
        spec = self.spec(mission_id)
        if (action not in SENSITIVE or action in spec.forbidden_actions or
                decide(action, spec.merge_policy) != Decision.OWNER_APPROVAL_REQUIRED or
                mission["current_head"] != head):
            return False
        row = self.db.execute(
            "SELECT decision,spec_sha256 FROM approvals WHERE mission_id=? AND action=? AND head_sha=? "
            "ORDER BY id DESC LIMIT 1", (mission_id, action, head)).fetchone()
        return row is not None and row[0] == "APPROVED" and row[1] == self._spec_digest(mission_id)

    @staticmethod
    def _proc_start_ticks(pid: int) -> str | None:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            comm_end = stat.rfind(")")
            if comm_end < 0:
                return None
            fields = stat[comm_end + 2 :].split()
            return fields[19] if len(fields) > 19 else None
        except (FileNotFoundError, IndexError, ValueError):
            return None

    def claim_merge(self, mission_id: str, head: str, owner_pid: int | None = None,
                    owner_start_ticks: str | None = None) -> bool:
        """One durable claimant may invoke an external merge for one exact HEAD."""
        owner_pid = os.getpid() if owner_pid is None else owner_pid
        owner_start_ticks = self._proc_start_ticks(owner_pid) if owner_start_ticks is None else owner_start_ticks
        if owner_start_ticks is None:
            raise RuntimeError("cannot claim merge without an owner start-time identity")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT current_state,current_head,merge_claim_head FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if State(row["current_state"]) != State.MERGE or row["current_head"] != head or row["merge_claim_head"] is not None:
                self.db.commit()
                return False
            self.db.execute("UPDATE missions SET merge_claim_head=?,merge_claim_pid=?,merge_claim_start_ticks=?,updated_at=? WHERE mission_id=? AND merge_claim_head IS NULL",
                            (head, owner_pid, owner_start_ticks, now(), mission_id))
            self.event(mission_id, "merge_claimed", {"head": head, "owner_pid": owner_pid,
                                                      "owner_start_ticks": owner_start_ticks})
            self.db.commit()
            return True
        except Exception:
            self.db.rollback()
            raise

    def reclaim_merge_claim_if_stale(self, mission_id: str, head: str) -> str:
        """Reclaim only a claim whose recorded owner is definitely gone.

        A live owner remains authoritative even when canonical merge status is
        ``NOT_STARTED``; another controller must never erase that claim between
        its status check and its external merge call. Unknown owner identity is
        fail-closed for pre-migration or malformed claims.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,merge_claim_head,merge_claim_pid,merge_claim_start_ticks "
                "FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if (State(row["current_state"]) != State.MERGE or row["current_head"] != head or
                    row["merge_claim_head"] != head):
                self.db.commit()
                return "NO_CLAIM"
            pid, start_ticks = row["merge_claim_pid"], row["merge_claim_start_ticks"]
            if not isinstance(pid, int) or not start_ticks:
                self.db.commit()
                return "UNKNOWN"
            if self._proc_start_ticks(pid) == start_ticks:
                self.db.commit()
                return "ACTIVE"
            changed = self.db.execute(
                "UPDATE missions SET merge_claim_head=NULL,merge_claim_pid=NULL,merge_claim_start_ticks=NULL,updated_at=? "
                "WHERE mission_id=? AND current_state=? AND current_head=? AND merge_claim_head=? "
                "AND merge_claim_pid=? AND merge_claim_start_ticks=?",
                (now(), mission_id, State.MERGE, head, head, pid, start_ticks)).rowcount
            if changed != 1:
                self.db.commit()
                return "NO_CLAIM"
            self.event(mission_id, "merge_claim_reclaimed", {"head": head, "owner_pid": pid,
                                                               "owner_start_ticks": start_ticks})
            self.db.commit()
            return "RECLAIMED"
        except Exception:
            self.db.rollback()
            raise


    def status(self, mission_id: str) -> Observation:
        row = self.mission(mission_id)
        jobs = self.db.execute("SELECT count(*) FROM jobs WHERE mission_id=? AND state IN ('STARTING','RUNNING')", (mission_id,)).fetchone()[0]
        return Observation(State(row["current_state"]), row["current_head"], row["worktree"],
                           row["pending_gate"], jobs, row["terminal_state"] is not None)

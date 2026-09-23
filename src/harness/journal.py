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
              codex_turn_id TEXT, codex_turn_state TEXT, codex_turn_pid INTEGER,
              codex_turn_start_ticks TEXT, codex_turn_source_state TEXT,
              codex_turn_source_head TEXT,
              current_state TEXT NOT NULL, pending_gate TEXT, completed_gates_json TEXT NOT NULL DEFAULT '{}',
              ci_state TEXT, approval_state TEXT NOT NULL DEFAULT 'NONE', terminal_state TEXT,
              merge_claim_head TEXT,
              merge_claim_pr_number INTEGER,
              merge_claim_pr_repo TEXT,
              merge_invocation_started INTEGER NOT NULL DEFAULT 0,
              merge_claim_pid INTEGER,
              merge_claim_start_ticks TEXT,
              pr_number INTEGER, pr_repo TEXT, merge_sha TEXT, main_sha TEXT, tree_sha TEXT,
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
              decision TEXT NOT NULL, reason TEXT, head_sha TEXT, pr_number INTEGER, pr_repo TEXT,
              spec_sha256 TEXT, created_at TEXT NOT NULL);
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
        if "pr_number" not in approval_columns:
            self.db.execute("ALTER TABLE approvals ADD COLUMN pr_number INTEGER")
        if "pr_repo" not in approval_columns:
            self.db.execute("ALTER TABLE approvals ADD COLUMN pr_repo TEXT")
        mission_columns = {row[1] for row in self.db.execute("PRAGMA table_info(missions)")}
        for name, definition in (("codex_turn_id", "TEXT"), ("codex_turn_state", "TEXT"),
                                 ("codex_turn_pid", "INTEGER"), ("codex_turn_start_ticks", "TEXT"),
                                 ("codex_turn_source_state", "TEXT"),
                                 ("codex_turn_source_head", "TEXT")):
            if name not in mission_columns:
                self.db.execute(f"ALTER TABLE missions ADD COLUMN {name} {definition}")
        mission_columns = {row[1] for row in self.db.execute("PRAGMA table_info(missions)")}
        if "merge_claim_head" not in mission_columns:
            self.db.execute("ALTER TABLE missions ADD COLUMN merge_claim_head TEXT")
        for name, definition in (("merge_claim_pr_number", "INTEGER"), ("merge_claim_pr_repo", "TEXT"),
                                 ("merge_invocation_started", "INTEGER NOT NULL DEFAULT 0"),
                                 ("merge_claim_pid", "INTEGER"), ("merge_claim_start_ticks", "TEXT")):
            if name not in mission_columns:
                self.db.execute(f"ALTER TABLE missions ADD COLUMN {name} {definition}")
        mission_columns = {row[1] for row in self.db.execute("PRAGMA table_info(missions)")}
        for name, definition in (("pr_number", "INTEGER"), ("pr_repo", "TEXT"), ("merge_sha", "TEXT"),
                                 ("main_sha", "TEXT"), ("tree_sha", "TEXT")):
            if name not in mission_columns:
                self.db.execute(f"ALTER TABLE missions ADD COLUMN {name} {definition}")
        self.db.commit()

    def create(self, spec: MissionSpec, *, worktree: str | None = None,
               base_sha: str | None = None, branch: str | None = None) -> None:
        stamp = now()
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute(
                "INSERT INTO missions(mission_id,spec_json,repo,base_sha,branch,worktree,current_state,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (spec.mission_id, json.dumps(spec.__dict__), spec.repository, base_sha, branch,
                 worktree, State.CREATED, stamp, stamp),
            )
            self.event(spec.mission_id, "mission_created", {"schema_version": spec.schema_version})
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

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

    def transition(self, mission_id: str, target: State, reason: str, *,
                   expected_state: State | None = None,
                   expected_head: str | None = None) -> None:
        """Commit one state transition from a writer-locked exact snapshot.

        The state and HEAD predicates are repeated in the UPDATE so a stale
        controller cannot publish a decision after another controller has
        reconciled either value.  ``expected_head=None`` means that the caller
        has no stronger HEAD assertion; the locked journal HEAD is still part
        of the compare-and-swap predicate.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError(mission_id)
            source = State(row["current_state"])
            head = row["current_head"]
            if expected_state is not None and source != expected_state:
                raise InvalidTransition(
                    f"stale transition expected state {expected_state}, observed {source}"
                )
            if expected_head is not None and head != expected_head:
                raise InvalidTransition(
                    f"stale transition expected HEAD {expected_head}, observed {head}"
                )
            if source in TERMINAL or target not in ALLOWED.get(source, set()):
                raise InvalidTransition(f"{source} -> {target} is forbidden")
            terminal = target if target in TERMINAL else None
            changed = self.db.execute(
                "UPDATE missions SET current_state=?,terminal_state=?,updated_at=? "
                "WHERE mission_id=? AND current_state=? AND current_head IS ?",
                (target, terminal, now(), mission_id, source, head),
            ).rowcount
            if changed != 1:
                raise InvalidTransition("state or HEAD changed during transition")
            self.event(mission_id, "state_transition", {
                "from": source, "to": target, "head": head, "reason": reason,
            })
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def complete_merge(self, mission_id: str, reviewed_head: str, *,
                       pr_number: int, pr_repo: str, merge_sha: str | None,
                       reason: str) -> None:
        """Atomically publish merge evidence and leave MERGE.

        Keeping the claim until this transaction prevents a crash between
        recording the external result and advancing the state from making a
        second merge invocation appear safe.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,merge_claim_head,merge_claim_pr_number,"
                "merge_claim_pr_repo FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if (State(row["current_state"]) != State.MERGE
                    or row["current_head"] != reviewed_head
                    or row["merge_claim_head"] != reviewed_head
                    or row["merge_claim_pr_number"] != pr_number
                    or row["merge_claim_pr_repo"] != pr_repo):
                raise InvalidTransition("merge completion lost its exact claim or PR identity")
            changed = self.db.execute(
                "UPDATE missions SET current_state=?,terminal_state=NULL,pending_gate=NULL,"
                "pr_number=?,pr_repo=?,merge_sha=?,merge_claim_head=NULL,"
                "merge_claim_pr_number=NULL,merge_claim_pr_repo=NULL,merge_invocation_started=0,"
                "merge_claim_pid=NULL,merge_claim_start_ticks=NULL,updated_at=? "
                "WHERE mission_id=? AND current_state=? AND current_head=? AND merge_claim_head=? "
                "AND merge_claim_pr_number=? AND merge_claim_pr_repo=?",
                (State.POST_MERGE, pr_number, pr_repo, merge_sha, now(), mission_id,
                 State.MERGE, reviewed_head, reviewed_head, pr_number, pr_repo),
            ).rowcount
            if changed != 1:
                raise InvalidTransition("merge completion lost its exact state snapshot")
            self.event(mission_id, "merge_completed", {
                "reviewed_head": reviewed_head, "pr_number": pr_number,
                "pr_repo": pr_repo, "merge_sha": merge_sha,
            })
            self.event(mission_id, "state_transition", {
                "from": State.MERGE, "to": State.POST_MERGE,
                "head": reviewed_head, "reason": reason,
            })
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def update(self, mission_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = now()
        keys = list(fields)
        self.db.execute("UPDATE missions SET " + ",".join(f"{k}=?" for k in keys) + " WHERE mission_id=?",
                        [fields[k] for k in keys] + [mission_id])
        self.db.commit()

    def complete_gate(self, mission_id: str, gate: str, head: str) -> None:
        """Atomically publish one gate result against its exact launch snapshot."""
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,pending_gate,completed_gates_json "
                "FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if (State(row["current_state"]) != State.TEST or
                    row["current_head"] != head or row["pending_gate"] != gate):
                raise InvalidTransition(
                    "gate completion is stale for current state, HEAD, or pending gate"
                )
            gates = json.loads(row["completed_gates_json"])
            if isinstance(gates, list):  # v0.1 pre-release journal migration
                gates = {name: None for name in gates}
            if not isinstance(gates, dict):
                raise RuntimeError("completed gate journal is invalid")
            gates[gate] = head
            changed = self.db.execute(
                "UPDATE missions SET completed_gates_json=?,pending_gate=NULL,updated_at=? "
                "WHERE mission_id=? AND current_state=? AND current_head=? AND pending_gate=?",
                (json.dumps(gates), now(), mission_id, State.TEST, head, gate),
            ).rowcount
            if changed != 1:
                raise InvalidTransition("gate completion lost its source snapshot")
            self.event(mission_id, "gate_pass", {"gate": gate, "head": head})
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def gate_passed_at_head(self, mission_id: str, gate: str, head: str) -> bool:
        gates = json.loads(self.mission(mission_id)["completed_gates_json"])
        return isinstance(gates, dict) and gates.get(gate) == head

    def bind_pr_identity(self, mission_id: str, head: str, pr_number: int, pr_repo: str) -> bool:
        """Persist CI's PR identity only for the current exact CI snapshot."""
        if (not isinstance(pr_number, int) or pr_number <= 0 or not isinstance(pr_repo, str)
                or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pr_repo) is None):
            return False
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,pr_number,pr_repo FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if (row is None or State(row["current_state"]) != State.CI
                    or row["current_head"] != head
                    or row["pr_number"] not in {None, pr_number}
                    or row["pr_repo"] not in {None, pr_repo}):
                self.db.commit()
                return False
            changed = self.db.execute(
                "UPDATE missions SET pr_number=?,pr_repo=?,updated_at=? WHERE mission_id=? "
                "AND current_state=? AND current_head=? AND (pr_number IS NULL OR pr_number=?) "
                "AND (pr_repo IS NULL OR pr_repo=?)",
                (pr_number, pr_repo, now(), mission_id, State.CI, head, pr_number, pr_repo),
            ).rowcount
            if changed == 1:
                self.event(mission_id, "pr_identity_bound", {"head": head, "pr": pr_number, "repo": pr_repo})
            self.db.commit()
            return changed == 1
        except Exception:
            self.db.rollback()
            raise

    def record_receipt(self, mission_id: str, reviewer: str, head: str, result: str, artifact: str | None = None) -> None:
        self.db.execute("INSERT INTO receipts(mission_id,reviewer,head_sha,result,artifact_path,created_at) VALUES(?,?,?,?,?,?)",
                        (mission_id, reviewer, head, result, artifact, now()))
        self.event(mission_id, "review_result", {"reviewer": reviewer, "head": head, "result": result})
        self.db.commit()

    def invalidate_reviews(self, mission_id: str, current_head: str) -> int:
        try:
            result = self.db.execute(
                "UPDATE receipts SET invalidated=1 WHERE mission_id=? AND head_sha<>? AND invalidated=0",
                (mission_id, current_head),
            )
            if result.rowcount:
                self.event(mission_id, "reviews_invalidated", {
                    "current_head": current_head, "count": result.rowcount,
                })
            # Even a zero-row UPDATE opens sqlite3's implicit transaction.
            # Commit every path so a later BEGIN IMMEDIATE cannot inherit a
            # stale no-op transaction.
            self.db.commit()
            return result.rowcount
        except Exception:
            self.db.rollback()
            raise

    def reconcile_head(self, mission_id: str, head: str) -> bool:
        """Atomically replace cached HEAD and revoke all downstream acceptance facts."""
        try:
            self.db.execute("BEGIN IMMEDIATE")
            # Read after the writer lock: another controller cannot race a stale
            # state decision into a later terminal acceptance.
            row = self.db.execute(
                "SELECT current_head,current_state,merge_claim_head,codex_turn_state,"
                "codex_turn_source_head FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if row["current_head"] == head:
                self.db.commit()
                return False
            source = State(row["current_state"])
            changed = self.db.execute(
                "UPDATE missions SET current_head=?,updated_at=? WHERE mission_id=? "
                "AND current_head IS ? AND current_state=? AND merge_claim_head IS ? "
                "AND codex_turn_state IS ? AND codex_turn_source_head IS ?",
                (head, now(), mission_id, row["current_head"], source,
                 row["merge_claim_head"], row["codex_turn_state"],
                 row["codex_turn_source_head"]),
            ).rowcount
            if changed != 1:
                raise InvalidTransition("canonical HEAD reconcile lost its source snapshot")
            if (row["codex_turn_state"] == "COMPLETED" and
                    row["codex_turn_source_head"] != head):
                self.db.execute(
                    "UPDATE missions SET codex_turn_state='STALE',updated_at=? WHERE mission_id=? "
                    "AND codex_turn_state='COMPLETED'",
                    (now(), mission_id),
                )
                self.event(mission_id, "codex_turn_stale_on_head_reconcile", {
                    "source_head": row["codex_turn_source_head"], "current_head": head,
                })
            invalidated = self.db.execute("UPDATE receipts SET invalidated=1 WHERE mission_id=? AND head_sha<>? AND invalidated=0",
                                          (mission_id, head)).rowcount
            if source == State.PASS:
                changed = self.db.execute("UPDATE missions SET current_state=?,terminal_state=NULL,pending_gate=NULL,ci_state=NULL,approval_state='NONE',pr_number=NULL,pr_repo=NULL,merge_sha=NULL,main_sha=NULL,tree_sha=NULL,merge_claim_head=NULL,merge_claim_pr_number=NULL,merge_claim_pr_repo=NULL,merge_invocation_started=0,merge_claim_pid=NULL,merge_claim_start_ticks=NULL,updated_at=? WHERE mission_id=? AND current_state=? AND current_head=?",
                                          (State.TEST, now(), mission_id, source, head)).rowcount
                if changed != 1:
                    raise InvalidTransition("PASS reopen lost its reconciled source snapshot")
                self.event(mission_id, "pass_reopened_for_new_head", {"reason": "canonical HEAD changed after PASS"})
            elif source == State.MERGE and row["merge_claim_head"] is not None:
                # HEAD drift invalidates source-bound acceptance, but an
                # external merge may still be in flight behind this durable
                # claim. Preserve it until canonical merge status and the
                # recorded owner identity prove that retrying is safe.
                changed = self.db.execute(
                    "UPDATE missions SET terminal_state=NULL,pending_gate=NULL,ci_state=NULL,"
                    "approval_state='NONE',updated_at=? WHERE mission_id=? "
                    "AND current_state=? AND current_head=? AND merge_claim_head=?",
                    (now(), mission_id, source, head, row["merge_claim_head"]),
                ).rowcount
                if changed != 1:
                    raise InvalidTransition("merge claim preservation lost its reconciled snapshot")
                self.event(mission_id, "merge_claim_preserved_on_head_drift", {
                    "claim_head": row["merge_claim_head"], "current_head": head,
                })
            elif source in {State.REVIEW, State.CI, State.MERGE, State.WAITING_APPROVAL, State.POST_MERGE, State.DELIVER}:
                changed = self.db.execute("UPDATE missions SET current_state=?,terminal_state=NULL,pending_gate=NULL,ci_state=NULL,approval_state='NONE',pr_number=NULL,pr_repo=NULL,merge_sha=NULL,main_sha=NULL,tree_sha=NULL,merge_claim_head=NULL,merge_claim_pr_number=NULL,merge_claim_pr_repo=NULL,merge_invocation_started=0,merge_claim_pid=NULL,merge_claim_start_ticks=NULL,updated_at=? WHERE mission_id=? AND current_state=? AND current_head=?",
                                          (State.TEST, now(), mission_id, source, head)).rowcount
                if changed != 1:
                    raise InvalidTransition("state rewind lost its reconciled source snapshot")
                self.event(mission_id, "state_reconciled_to_test", {"from": source, "reason": "canonical HEAD changed"})
            self.event(mission_id, "canonical_head_reconciled", {"head": head, "invalidated_reviews": invalidated})
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return True

    def valid_reviews(self, mission_id: str, head: str) -> set[str]:
        rows = self.db.execute(
            "SELECT receipt.reviewer FROM receipts AS receipt "
            "WHERE receipt.mission_id=? AND receipt.head_sha=? "
            "AND receipt.result='PASS' AND receipt.invalidated=0 "
            "AND receipt.id=(SELECT MAX(latest.id) FROM receipts AS latest "
            "WHERE latest.mission_id=receipt.mission_id "
            "AND latest.head_sha=receipt.head_sha AND latest.reviewer=receipt.reviewer)",
            (mission_id, head),
        ).fetchall()
        return {row[0] for row in rows}

    def approve(self, mission_id: str, action: str, reason: str = "", observed_head: str | None = None) -> None:
        if observed_head is None:
            raise RuntimeError("approval requires an explicitly observed canonical HEAD")
        try:
            self.db.execute("BEGIN IMMEDIATE")
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
            if observed_head != head:
                raise RuntimeError("observed canonical HEAD differs from journal HEAD")
            if (State(mission["current_state"]) != State.WAITING_APPROVAL or
                    mission["approval_state"] != "PENDING" or
                    mission["pending_gate"] != f"owner-{action}" or
                    (action == "merge" and (mission["pr_number"] is None or mission["pr_repo"] is None))):
                raise RuntimeError(f"mission is not waiting for approval of action: {action}")
            spec_digest = self._spec_digest(mission_id)
            self.db.execute(
                "INSERT INTO approvals(mission_id,action,decision,reason,head_sha,pr_number,pr_repo,spec_sha256,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (mission_id, action, "APPROVED", reason, head, mission["pr_number"], mission["pr_repo"], spec_digest, now()),
            )
            changed = self.db.execute(
                "UPDATE missions SET approval_state='APPROVED',updated_at=? "
                "WHERE mission_id=? AND current_head=? AND current_state=? "
                "AND approval_state='PENDING' AND pending_gate=?",
                (now(), mission_id, head, State.WAITING_APPROVAL, f"owner-{action}"),
            ).rowcount
            if changed != 1:
                raise RuntimeError("approval source state or canonical HEAD changed")
            self.event(mission_id, "approval_granted", {
                "action": action, "head": head,
                "spec_sha256": spec_digest, "reason": reason,
            })
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def approved(self, mission_id: str, action: str, head: str) -> bool:
        mission = self.mission(mission_id)
        spec = self.spec(mission_id)
        if (action not in SENSITIVE or action in spec.forbidden_actions or
                decide(action, spec.merge_policy) != Decision.OWNER_APPROVAL_REQUIRED or
                mission["current_head"] != head):
            return False
        row = self.db.execute(
            "SELECT decision,spec_sha256,pr_number,pr_repo FROM approvals WHERE mission_id=? AND action=? AND head_sha=? "
            "ORDER BY id DESC LIMIT 1", (mission_id, action, head)).fetchone()
        return (row is not None and row[0] == "APPROVED" and row[1] == self._spec_digest(mission_id)
                and (action != "merge" or (row[2] == mission["pr_number"] and row[3] == mission["pr_repo"])))

    def claim_codex_turn(self, mission_id: str, owner_pid: int | None = None,
                         owner_start_ticks: str | None = None) -> str:
        """Durably serialize one primary Codex turn per mission.

        A live claim is returned to the caller as ``ACTIVE`` and can never be
        stolen.  A claim whose owner is gone has an unknown turn outcome, so it
        is reported as ``UNKNOWN`` and must fail closed instead of replaying a
        possibly completed turn.
        """
        owner_pid = os.getpid() if owner_pid is None else owner_pid
        owner_start_ticks = self._proc_start_ticks(owner_pid) if owner_start_ticks is None else owner_start_ticks
        if owner_start_ticks is None:
            raise RuntimeError("cannot claim Codex turn without owner start-time identity")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,codex_turn_state,codex_turn_id,codex_turn_pid,"
                "codex_turn_start_ticks,codex_turn_source_state,codex_turn_source_head "
                "FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if State(row["current_state"]) not in {State.IMPLEMENT, State.REVIEW, State.CI}:
                self.db.commit()
                return "NOT_IMPLEMENT"
            if row["codex_turn_state"] == "RUNNING":
                if (row["codex_turn_source_state"] != row["current_state"] or
                        row["codex_turn_source_head"] != row["current_head"]):
                    self.db.commit()
                    return "UNKNOWN"
                pid, start = row["codex_turn_pid"], row["codex_turn_start_ticks"]
                if isinstance(pid, int) and start and self._proc_start_ticks(pid) == start:
                    self.db.commit()
                    return "ACTIVE"
                self.db.commit()
                return "UNKNOWN"
            if row["codex_turn_state"] == "COMPLETED":
                # The provider turn may have completed and been journaled just
                # before the controller crashed.  Let the supervisor consume
                # that durable completion atomically with the source-state
                # transition instead of starting the same writable turn again.
                if (row["codex_turn_id"] and
                        row["codex_turn_source_state"] == row["current_state"] and
                        row["codex_turn_source_head"] == row["current_head"]):
                    self.db.commit()
                    return "COMPLETED"
                self.db.execute(
                    "UPDATE missions SET codex_turn_state='STALE',updated_at=? "
                    "WHERE mission_id=? AND codex_turn_state='COMPLETED'",
                    (now(), mission_id),
                )
                self.event(mission_id, "codex_turn_stale", {
                    "source_state": row["codex_turn_source_state"],
                    "source_head": row["codex_turn_source_head"],
                    "current_state": row["current_state"],
                    "current_head": row["current_head"],
                })
                self.db.commit()
                return "STALE"
            if row["codex_turn_state"] == "STALE":
                self.db.commit()
                return "STALE"
            changed = self.db.execute(
                "UPDATE missions SET codex_turn_state='RUNNING',codex_turn_id=NULL,"
                "codex_turn_pid=?,codex_turn_start_ticks=?,codex_turn_source_state=current_state,"
                "codex_turn_source_head=current_head,updated_at=? "
                "WHERE mission_id=? AND current_state IN (?,?,?) AND current_head IS ? "
                "AND COALESCE(codex_turn_state,'') NOT IN ('RUNNING','COMPLETED','STALE')",
                (owner_pid, owner_start_ticks, now(), mission_id, State.IMPLEMENT,
                 State.REVIEW, State.CI, row["current_head"]),
            ).rowcount
            if changed != 1:
                self.db.commit()
                return "ACTIVE"
            self.event(mission_id, "codex_turn_claimed", {
                "owner_pid": owner_pid, "owner_start_ticks": owner_start_ticks,
                "source_state": row["current_state"], "source_head": row["current_head"],
            })
            self.db.commit()
            return "CLAIMED"
        except Exception:
            self.db.rollback()
            raise

    def discard_stale_codex_turn(self, mission_id: str, *,
                                 expected_state: State,
                                 expected_head: str | None) -> bool:
        """Discard only a provably completed turn for an obsolete source snapshot.

        STALE is not replayable evidence.  A valid completed turn may be retired
        once its recorded source state or HEAD differs from the current guarded
        snapshot, allowing a later controller iteration to claim a fresh turn.
        Missing completion identity or a matching source snapshot remains
        fail-closed as journal corruption/ambiguity.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,codex_turn_state,codex_turn_id,"
                "codex_turn_source_state,codex_turn_source_head "
                "FROM missions WHERE mission_id=?", (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError(mission_id)
            source = State(row["current_state"])
            head = row["current_head"]
            if source != expected_state or head != expected_head:
                raise InvalidTransition("stale turn reset lost its source state or HEAD")
            obsolete = (row["codex_turn_source_state"] != source or
                        row["codex_turn_source_head"] != head)
            if (row["codex_turn_state"] != "STALE" or
                    not row["codex_turn_id"] or not obsolete):
                self.db.commit()
                return False
            changed = self.db.execute(
                "UPDATE missions SET codex_turn_state='DISCARDED',updated_at=? "
                "WHERE mission_id=? AND current_state=? AND current_head IS ? "
                "AND codex_turn_state='STALE' AND codex_turn_id=? "
                "AND codex_turn_source_state IS ? AND codex_turn_source_head IS ?",
                (now(), mission_id, source, head, row["codex_turn_id"],
                 row["codex_turn_source_state"], row["codex_turn_source_head"]),
            ).rowcount
            if changed != 1:
                raise InvalidTransition("stale turn reset lost its completion snapshot")
            self.event(mission_id, "codex_turn_stale_discarded", {
                "turn_id": row["codex_turn_id"],
                "source_state": row["codex_turn_source_state"],
                "source_head": row["codex_turn_source_head"],
                "current_state": source, "current_head": head,
            })
            self.db.commit()
            return True
        except Exception:
            self.db.rollback()
            raise

    def record_codex_thread(self, mission_id: str, thread_id: str, owner_pid: int,
                            owner_start_ticks: str) -> None:
        try:
            changed = self.db.execute(
                "UPDATE missions SET codex_thread_id=?,updated_at=? WHERE mission_id=? "
                "AND codex_turn_state='RUNNING' AND codex_turn_pid=? AND codex_turn_start_ticks=?",
                (thread_id, now(), mission_id, owner_pid, owner_start_ticks),
            ).rowcount
            if changed != 1:
                raise RuntimeError("Codex turn lease was lost before thread persistence")
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def complete_codex_turn(self, mission_id: str, turn_id: str, owner_pid: int,
                            owner_start_ticks: str) -> None:
        try:
            changed = self.db.execute(
                "UPDATE missions SET codex_turn_id=?,codex_turn_state='COMPLETED',updated_at=? "
                "WHERE mission_id=? AND codex_turn_state='RUNNING' AND codex_turn_pid=? "
                "AND codex_turn_start_ticks=? AND current_state=codex_turn_source_state "
                "AND current_head IS codex_turn_source_head",
                (turn_id, now(), mission_id, owner_pid, owner_start_ticks),
            ).rowcount
            if changed != 1:
                raise RuntimeError("Codex turn lease was lost before completion persistence")
            self.event(mission_id, "codex_turn_completed", {"turn_id": turn_id})
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def transition_after_codex_turn(self, mission_id: str, target: State, reason: str, *,
                                    expected_state: State, expected_head: str | None) -> None:
        """Consume a completed turn and advance its source state in one commit.

        A controller can crash after ``complete_codex_turn`` but before the
        normal state transition.  The ``COMPLETED`` marker is therefore a
        durable hand-off, not permission to claim another turn.  This method
        consumes it under the same writer lock as the state/HEAD CAS so a
        resumed mission advances exactly once.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,codex_turn_state,codex_turn_id,"
                "codex_turn_source_state,codex_turn_source_head "
                "FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            source = State(row["current_state"])
            head = row["current_head"]
            if source != expected_state:
                raise InvalidTransition(
                    f"stale turn transition expected state {expected_state}, observed {source}"
                )
            if expected_head is not None and head != expected_head:
                raise InvalidTransition(
                    f"stale turn transition expected HEAD {expected_head}, observed {head}"
                )
            if row["codex_turn_state"] != "COMPLETED" or not row["codex_turn_id"]:
                raise InvalidTransition("no unconsumed completed Codex turn")
            if (row["codex_turn_source_state"] != source or
                    row["codex_turn_source_head"] != head):
                raise InvalidTransition("completed Codex turn is stale for current state or HEAD")
            if source in TERMINAL or target not in ALLOWED.get(source, set()):
                raise InvalidTransition(f"{source} -> {target} is forbidden")
            changed = self.db.execute(
                "UPDATE missions SET current_state=?,terminal_state=?,codex_turn_state='CONSUMED',"
                "updated_at=? WHERE mission_id=? AND current_state=? AND current_head IS ? "
                "AND codex_turn_state='COMPLETED' AND codex_turn_id IS NOT NULL "
                "AND codex_turn_source_state=? AND codex_turn_source_head IS ?",
                (target, target if target in TERMINAL else None, now(), mission_id,
                 source, head, source, head),
            ).rowcount
            if changed != 1:
                raise InvalidTransition("turn completion or source identity changed during transition")
            self.event(mission_id, "state_transition", {
                "from": source, "to": target, "head": head, "reason": reason,
                "consumed_codex_turn": row["codex_turn_id"],
            })
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def fail_codex_turn(self, mission_id: str, reason: str, owner_pid: int,
                        owner_start_ticks: str) -> None:
        try:
            changed = self.db.execute(
                "UPDATE missions SET codex_turn_state='FAILED',updated_at=? WHERE mission_id=? "
                "AND codex_turn_state='RUNNING' AND codex_turn_pid=? AND codex_turn_start_ticks=?",
                (now(), mission_id, owner_pid, owner_start_ticks),
            ).rowcount
            if changed:
                self.event(mission_id, "codex_turn_failed", {"reason": reason})
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    @staticmethod
    def _proc_identity(pid: int) -> tuple[str, str | None]:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            comm_end = stat.rfind(")")
            if comm_end < 0:
                return "UNKNOWN", None
            fields = stat[comm_end + 2 :].split()
            return ("PRESENT", fields[19]) if len(fields) > 19 else ("UNKNOWN", None)
        except FileNotFoundError:
            return "ABSENT", None
        except (OSError, IndexError, ValueError):
            return "UNKNOWN", None

    @staticmethod
    def _proc_start_ticks(pid: int) -> str | None:
        status, ticks = Journal._proc_identity(pid)
        return ticks if status == "PRESENT" else None

    def claim_merge(self, mission_id: str, head: str, owner_pid: int | None = None,
                    owner_start_ticks: str | None = None) -> bool:
        """One durable claimant may invoke an external merge for one exact HEAD."""
        owner_pid = os.getpid() if owner_pid is None else owner_pid
        owner_start_ticks = self._proc_start_ticks(owner_pid) if owner_start_ticks is None else owner_start_ticks
        if owner_start_ticks is None:
            raise RuntimeError("cannot claim merge without an owner start-time identity")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT current_state,current_head,merge_claim_head,pr_number,pr_repo FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if (State(row["current_state"]) != State.MERGE or row["current_head"] != head
                    or row["merge_claim_head"] is not None or row["pr_number"] is None or not row["pr_repo"]):
                self.db.commit()
                return False
            changed = self.db.execute(
                "UPDATE missions SET merge_claim_head=?,merge_claim_pr_number=?,merge_claim_pr_repo=?,"
                "merge_invocation_started=0,merge_claim_pid=?,"
                "merge_claim_start_ticks=?,updated_at=? WHERE mission_id=? "
                "AND current_state=? AND current_head=? AND merge_claim_head IS NULL "
                "AND pr_number=? AND pr_repo=?",
                (head, row["pr_number"], row["pr_repo"], owner_pid, owner_start_ticks, now(),
                 mission_id, State.MERGE, head, row["pr_number"], row["pr_repo"]),
            ).rowcount
            if changed != 1:
                self.db.commit()
                return False
            self.event(mission_id, "merge_claimed", {"head": head, "pr": row["pr_number"],
                                                      "repo": row["pr_repo"], "owner_pid": owner_pid,
                                                      "owner_start_ticks": owner_start_ticks})
            self.db.commit()
            return True
        except Exception:
            self.db.rollback()
            raise

    def mark_merge_invocation_started(self, mission_id: str, claim_head: str,
                                      owner_pid: int, owner_start_ticks: str) -> bool:
        """Durably mark the point after which an external merge may have started."""
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,merge_claim_head,merge_claim_pid,"
                "merge_claim_start_ticks,merge_claim_pr_number,merge_claim_pr_repo,"
                "merge_invocation_started FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if (row is None or State(row["current_state"]) != State.MERGE
                    or row["current_head"] != claim_head or row["merge_claim_head"] != claim_head
                    or row["merge_claim_pid"] != owner_pid
                    or row["merge_claim_start_ticks"] != owner_start_ticks):
                self.db.commit()
                return False
            status, ticks = self._proc_identity(owner_pid)
            if status != "PRESENT" or ticks != owner_start_ticks:
                self.db.commit()
                return False
            changed = self.db.execute(
                "UPDATE missions SET merge_invocation_started=1,updated_at=? WHERE mission_id=? "
                "AND current_state=? AND current_head=? AND merge_claim_head=? "
                "AND merge_claim_pid=? AND merge_claim_start_ticks=? AND merge_invocation_started=0",
                (now(), mission_id, State.MERGE, claim_head, claim_head, owner_pid, owner_start_ticks),
            ).rowcount
            if changed == 1:
                self.event(mission_id, "merge_invocation_started", {
                    "head": claim_head, "pr": row["merge_claim_pr_number"],
                    "repo": row["merge_claim_pr_repo"], "owner_pid": owner_pid,
                    "owner_start_ticks": owner_start_ticks,
                })
            self.db.commit()
            return changed == 1
        except Exception:
            self.db.rollback()
            raise

    def claim_merge_recovery(self, mission_id: str, claim_head: str,
                             recovery_pid: int, recovery_start_ticks: str) -> str:
        """Freeze a dead owner's claim under one live recovery controller.

        This writer-locked hand-off must happen before querying external merge
        status.  Once the old PID/start-time identity is definitely gone, it can
        no longer issue a merge after a recovery controller observes
        ``NOT_STARTED``.  Unknown owner identity remains fail-closed.
        """
        if not isinstance(recovery_pid, int) or recovery_pid <= 0 or not recovery_start_ticks:
            raise RuntimeError("cannot recover merge without a controller identity")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,merge_claim_head,merge_claim_pid,merge_claim_start_ticks,"
                "merge_claim_pr_number,merge_claim_pr_repo,merge_invocation_started "
                "FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if (State(row["current_state"]) != State.MERGE or
                    row["merge_claim_head"] != claim_head):
                self.db.commit()
                return "NO_CLAIM"
            claim_pr = row["merge_claim_pr_number"]
            claim_repo = row["merge_claim_pr_repo"]
            if (not isinstance(claim_pr, int) or claim_pr <= 0 or
                    not isinstance(claim_repo, str) or
                    re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", claim_repo) is None):
                self.db.commit()
                return "UNKNOWN"
            pid, start_ticks = row["merge_claim_pid"], row["merge_claim_start_ticks"]
            if not isinstance(pid, int) or not start_ticks:
                self.db.commit()
                return "UNKNOWN"
            owner_status, observed_ticks = self._proc_identity(pid)
            if owner_status == "UNKNOWN":
                self.db.commit()
                return "UNKNOWN"
            if owner_status == "PRESENT" and observed_ticks == start_ticks:
                self.db.commit()
                return "ACTIVE"
            current_head = row["current_head"]
            changed = self.db.execute(
                "UPDATE missions SET merge_claim_pid=?,merge_claim_start_ticks=?,updated_at=? "
                "WHERE mission_id=? AND current_state=? AND current_head IS ? AND merge_claim_head=? "
                "AND merge_claim_pid=? AND merge_claim_start_ticks=?",
                (recovery_pid, recovery_start_ticks, now(), mission_id, State.MERGE,
                 current_head, claim_head, pid, start_ticks),
            ).rowcount
            if changed != 1:
                self.db.commit()
                return "NO_CLAIM"
            self.event(mission_id, "merge_recovery_claimed", {
                "claim_head": claim_head, "current_head": current_head,
                "previous_owner_pid": pid, "previous_owner_start_ticks": start_ticks,
                "recovery_pid": recovery_pid,
                "recovery_start_ticks": recovery_start_ticks,
            })
            self.db.commit()
            return "RECOVERY_CLAIMED"
        except Exception:
            self.db.rollback()
            raise

    def confirm_merge_retry_safe(self, mission_id: str, claim_head: str,
                                 recovery_pid: int, recovery_start_ticks: str) -> str:
        """Bind a post-owner-death ``NOT_STARTED`` result to the recovery lease.

        The caller may retry only when this exact recovery identity still owns
        the claim and the canonical source HEAD has not drifted.  Drift clears
        the claim and atomically rewinds to TEST instead of merging either HEAD.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT current_state,current_head,merge_claim_head,merge_claim_pid,"
                "merge_claim_start_ticks,merge_invocation_started FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError(mission_id)
            if (State(row["current_state"]) != State.MERGE or
                    row["merge_claim_head"] != claim_head or
                    row["merge_claim_pid"] != recovery_pid or
                    row["merge_claim_start_ticks"] != recovery_start_ticks):
                self.db.commit()
                return "NO_CLAIM"
            if row["merge_invocation_started"]:
                self.db.commit()
                return "INVOCATION_STARTED"
            owner_status, observed_ticks = self._proc_identity(recovery_pid)
            if owner_status == "UNKNOWN":
                self.db.commit()
                return "UNKNOWN"
            if owner_status != "PRESENT" or observed_ticks != recovery_start_ticks:
                self.db.commit()
                return "NO_CLAIM"
            current_head = row["current_head"]
            if current_head != claim_head:
                changed = self.db.execute(
                    "UPDATE missions SET current_state=?,terminal_state=NULL,pending_gate=NULL,"
                    "ci_state=NULL,approval_state='NONE',pr_number=NULL,pr_repo=NULL,merge_sha=NULL,main_sha=NULL,tree_sha=NULL,merge_claim_head=NULL,"
                    "merge_claim_pr_number=NULL,merge_claim_pr_repo=NULL,merge_invocation_started=0,merge_claim_pid=NULL,merge_claim_start_ticks=NULL,updated_at=? "
                    "WHERE mission_id=? AND current_state=? AND current_head IS ? "
                    "AND merge_claim_head=? AND merge_claim_pid=? "
                    "AND merge_claim_start_ticks=?",
                    (State.TEST, now(), mission_id, State.MERGE, current_head,
                     claim_head, recovery_pid, recovery_start_ticks),
                ).rowcount
                if changed != 1:
                    self.db.commit()
                    return "NO_CLAIM"
                self.event(mission_id, "merge_claim_released_after_head_drift", {
                    "claim_head": claim_head, "current_head": current_head,
                    "recovery_pid": recovery_pid,
                    "recovery_start_ticks": recovery_start_ticks,
                })
                self.event(mission_id, "state_reconciled_to_test", {
                    "from": State.MERGE,
                    "reason": "canonical merge was not started and source HEAD changed",
                })
                self.db.commit()
                return "REWOUND_HEAD_DRIFT"
            self.event(mission_id, "merge_retry_authorized", {
                "claim_head": claim_head, "recovery_pid": recovery_pid,
                "recovery_start_ticks": recovery_start_ticks,
                "status": "NOT_STARTED",
            })
            self.db.commit()
            return "RETRY_SAFE"
        except Exception:
            self.db.rollback()
            raise

    def claim_uncertain_merge_reconciliation(self, mission_id: str, claim_head: str,
                                             owner_pid: int, owner_start_ticks: str) -> bool:
        """Atomically consume an unknown-outcome marker before querying status.

        The external merge call has returned, but its result was indeterminate.
        Exactly one controller may replace the prior owner and change the marker
        to ``merge-reconciling``; peers then observe an active non-stealable claim.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT merge_claim_pid,merge_claim_start_ticks,merge_invocation_started FROM missions "
                "WHERE mission_id=? AND current_state=? AND merge_claim_head=? "
                "AND pending_gate='merge-outcome-unknown'",
                (mission_id, State.MERGE, claim_head),
            ).fetchone()
            if row is None or row["merge_invocation_started"]:
                self.db.commit()
                return False
            changed = self.db.execute(
                "UPDATE missions SET merge_claim_pid=?,merge_claim_start_ticks=?,"
                "pending_gate='merge-reconciling',updated_at=? WHERE mission_id=? "
                "AND current_state=? AND merge_claim_head=? AND merge_claim_pid IS ? "
                "AND merge_claim_start_ticks IS ? AND pending_gate='merge-outcome-unknown' "
                "AND merge_invocation_started=0",
                (owner_pid, owner_start_ticks, now(), mission_id, State.MERGE,
                 claim_head, row["merge_claim_pid"], row["merge_claim_start_ticks"]),
            ).rowcount
            if changed:
                self.event(mission_id, "merge_uncertain_reconciliation_claimed", {
                    "claim_head": claim_head, "owner_pid": owner_pid,
                    "owner_start_ticks": owner_start_ticks,
                })
            self.db.commit()
            return changed == 1
        except Exception:
            self.db.rollback()
            raise


    def status(self, mission_id: str) -> Observation:
        row = self.mission(mission_id)
        jobs = self.db.execute("SELECT count(*) FROM jobs WHERE mission_id=? AND state IN ('STARTING','RUNNING')", (mission_id,)).fetchone()[0]
        return Observation(State(row["current_state"]), row["current_head"], row["worktree"],
                           row["pending_gate"], jobs, row["terminal_state"] is not None)

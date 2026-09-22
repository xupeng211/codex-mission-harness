from __future__ import annotations

from pathlib import Path

from .adapters import GateResult
from .codex import CodexAdapter
from .domain import MissionSpec, State, TERMINAL
from .isolation import docker_env
from .journal import Journal
from .policy import Decision, decide
from .process import ProcessSupervisor


class Supervisor:
    """State, gates and external observations decide completion; agent prose never does."""
    def __init__(self, journal: Journal, process: ProcessSupervisor, codex: CodexAdapter, adapter):
        self.journal, self.process, self.codex, self.adapter = journal, process, codex, adapter

    def create(self, spec: MissionSpec, worktree: str, base_sha: str, branch: str) -> None:
        self.journal.create(spec)
        self.journal.update(spec.mission_id, worktree=worktree, base_sha=base_sha, branch=branch)

    def reconcile(self, mission_id: str) -> None:
        row = self.journal.mission(mission_id)
        head = self.adapter.exact_head(row["worktree"])
        if head != row["current_head"]:
            self.journal.update(mission_id, current_head=head)
            self.journal.invalidate_reviews(mission_id, head)
            self.journal.event(mission_id, "canonical_head_reconciled", {"head": head})
            self.journal.db.commit()
        for result in self.process.poll(mission_id):
            if result.state == "EXITED" and result.exit_code == 0:
                pending = self.journal.mission(mission_id)["pending_gate"]
                if pending:
                    self.journal.complete_gate(mission_id, pending)
            elif result.state != "RUNNING":
                self.journal.transition(mission_id, State.FAILED_FATAL,
                                        f"owned process {result.state}: {result.exit_code}")

    def _agent_turn(self, mission_id: str, prompt: str) -> None:
        row = self.journal.mission(mission_id)
        thread = self.codex.start_or_resume(row["codex_thread_id"], row["worktree"])
        turn = self.codex.turn(thread, prompt, row["worktree"])
        self.journal.update(mission_id, codex_thread_id=thread)
        self.journal.event(mission_id, "codex_turn", {"thread_id": thread, "turn_id": turn.turn_id, "text": turn.text})
        self.journal.db.commit()

    def step(self, mission_id: str, spec: MissionSpec) -> State:
        self.reconcile(mission_id)
        row = self.journal.mission(mission_id)
        state = State(row["current_state"])
        if state in TERMINAL:
            return state
        if self.journal.status(mission_id).background_jobs:
            return state  # a running owned process is pending, never terminal or duplicate work
        if state == State.CREATED:
            self.journal.transition(mission_id, State.PREPARING, "mission accepted")
        elif state == State.PREPARING:
            self.journal.transition(mission_id, State.IMPLEMENT, "worktree prepared")
        elif state == State.IMPLEMENT:
            self._agent_turn(mission_id, "Continue the same mission. Inspect actual gates; do not declare terminal state from prose.")
            self.journal.transition(mission_id, State.TEST, "primary turn completed")
        elif state == State.TEST:
            for gate in spec.required_gates:
                if gate not in __import__("json").loads(row["completed_gates_json"]):
                    self.journal.update(mission_id, pending_gate=gate)
                    self.process.start(mission_id, gate, self.adapter.gate_argv(gate), row["worktree"], docker_env(mission_id))
                    return state
            self.journal.transition(mission_id, State.REVIEW, "local canonical gates pass")
        elif state == State.REVIEW:
            head = row["current_head"]
            valid = self.journal.valid_reviews(mission_id, head)
            for reviewer in spec.reviews:
                if reviewer not in valid:
                    result: GateResult = self.adapter.review(reviewer, head)
                    self.journal.record_receipt(mission_id, reviewer, head, result.status)
                    if result.status != "PASS":
                        self._agent_turn(mission_id, f"Repair reviewer {reviewer} findings: {result.evidence}")
                        self.journal.transition(mission_id, State.IMPLEMENT, "review finding is auto-remediable")
                        return State.IMPLEMENT
                    return state
            self.journal.transition(mission_id, State.CI, "all exact-head reviews pass")
        elif state == State.CI:
            result = self.adapter.ci(row["worktree"], row["current_head"])
            if result.status == "PASS":
                self.journal.transition(mission_id, State.MERGE, "canonical CI pass")
            elif result.status == "FAIL":
                self._agent_turn(mission_id, f"Repair canonical CI failure: {result.evidence}")
                self.journal.transition(mission_id, State.IMPLEMENT, "CI failure is auto-remediable")
            elif result.status == "BLOCKED_EXTERNAL":
                self.journal.transition(mission_id, State.BLOCKED_EXTERNAL, result.evidence)
            else:
                self.journal.update(mission_id, pending_gate="github-ci", ci_state=result.status)
        elif state == State.MERGE:
            if decide("merge", spec.merge_policy) == Decision.OWNER_APPROVAL_REQUIRED:
                self.journal.update(mission_id, approval_state="PENDING", pending_gate="owner-merge")
                self.journal.transition(mission_id, State.BLOCKED_POLICY, "owner merge approval required")
            else:
                self.journal.transition(mission_id, State.POST_MERGE, "merge canonical truth confirmed")
        elif state == State.POST_MERGE:
            self.journal.transition(mission_id, State.DELIVER, "post merge gates pass")
        elif state == State.DELIVER:
            self.journal.transition(mission_id, State.PASS, "terminal acceptance conditions verified")
        return State(self.journal.mission(mission_id)["current_state"])

    def run_until_wait(self, mission_id: str, spec: MissionSpec, limit: int = 50) -> State:
        for _ in range(limit):
            before = self.journal.status(mission_id)
            after = self.step(mission_id, spec)
            if after in TERMINAL or self.journal.status(mission_id).background_jobs or before.state == after == State.CI:
                return after
        raise RuntimeError("supervisor progress limit reached")

    def collect_jobs(self, mission_id: str) -> None:
        self.reconcile(mission_id)

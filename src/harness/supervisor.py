from __future__ import annotations

import subprocess
from pathlib import Path

from .adapters import GateResult, SimulatedAdapter
from .codex import CodexAdapter
from .domain import MissionSpec, State, TERMINAL
from .isolation import docker_env
from .journal import Journal
from .policy import Decision, decide, permitted
from .process import ProcessSupervisor


class Supervisor:
    """State, gates and external observations decide completion; agent prose never does."""
    def __init__(self, journal: Journal, process: ProcessSupervisor, codex: CodexAdapter, adapter):
        self.journal, self.process, self.codex, self.adapter = journal, process, codex, adapter

    def create(self, spec: MissionSpec, worktree: str, base_sha: str, branch: str) -> None:
        # Mission identity and its isolation metadata are one journal record;
        # a restart can never observe a half-created mission.
        self.journal.create(spec, worktree=worktree, base_sha=base_sha, branch=branch)

    def _merge_owner(self) -> tuple[int, str]:
        """Return this controller's pid/start-time identity for durable claims."""
        start_ticks = self.process.launcher_start_ticks
        if start_ticks is None:
            raise RuntimeError("cannot execute merge without controller start-time identity")
        return self.process.launcher_pid, start_ticks

    def reconcile(self, mission_id: str) -> None:
        row = self.journal.mission(mission_id)
        head = self.adapter.exact_head(row["worktree"])
        if head != row["current_head"]:
            # One transaction makes a crash observe either the old accepted HEAD or
            # a fully reopened mission; SQLite cache can never accept a hybrid.
            self.journal.reconcile_head(mission_id, head)
        for result in self.process.poll(mission_id):
            if result.state == "EXITED" and result.exit_code == 0:
                pending = self.journal.mission(mission_id)["pending_gate"]
                current = self.adapter.exact_head(row["worktree"])
                if pending and result.launch_head == current:
                    self.journal.complete_gate(mission_id, pending, current)
                elif pending:
                    self.journal.event(mission_id, "gate_stale", {"gate": pending, "launch_head": result.launch_head, "current_head": current})
            elif result.state == "LOST":
                # Canonical validation commands are idempotent: resume retries an unobserved outcome.
                self.journal.event(mission_id, "process_retry_required", {"job_id": result.job_id})
            elif result.state == "EXITED" and result.exit_code != 0:
                pending = self.journal.mission(mission_id)["pending_gate"]
                current = self.adapter.exact_head(self.journal.mission(mission_id)["worktree"])
                if result.launch_head != current:
                    # A failure from an older source identity is evidence about
                    # neither the current gate nor the current repair cycle.
                    # Keep the current journal state and force the normal
                    # exact-head validation path instead of attributing it to
                    # the new HEAD.
                    self.journal.event(mission_id, "gate_failure_stale", {
                        "gate": pending, "launch_head": result.launch_head, "current_head": current,
                        "exit_code": result.exit_code,
                    })
                elif pending and State(self.journal.mission(mission_id)["current_state"]) == State.TEST:
                    self.journal.event(mission_id, "gate_failed_auto_repair", {"gate": pending, "exit_code": result.exit_code})
                    self.journal.transition(mission_id, State.IMPLEMENT, f"canonical gate {pending} failed; repair required")
                else:
                    self.journal.transition(mission_id, State.FAILED_FATAL, f"owned process {result.state}: {result.exit_code}")
            elif result.state != "RUNNING":
                self.journal.transition(mission_id, State.FAILED_FATAL, f"owned process {result.state}: {result.exit_code}")

    def _agent_turn(self, mission_id: str, prompt: str, forbidden_actions: tuple[str, ...]) -> bool:
        owner_pid, owner_start_ticks = self._merge_owner()
        claim = self.journal.claim_codex_turn(mission_id, owner_pid, owner_start_ticks)
        if claim == "ACTIVE":
            return False
        if claim == "UNKNOWN":
            self.journal.transition(mission_id, State.BLOCKED_EXTERNAL,
                                    "previous Codex turn outcome is unknown after owner loss")
            return False
        if claim != "CLAIMED":
            return False
        row = self.journal.mission(mission_id)
        policy_text = ", ".join(forbidden_actions) if forbidden_actions else "(none)"
        guarded_prompt = (
            f"{prompt}\nMission forbidden_actions deny-list: {policy_text}. "
            "Never attempt a denied action; if the requested work would require one, "
            "stop and report the policy boundary. Before completing a source-changing "
            "turn, commit the intended changes so the exact source identity is clean "
            "and can be validated by the canonical gates."
        )
        try:
            setter = getattr(self.codex, "set_policy", None)
            if setter is not None:
                setter(forbidden_actions, row["worktree"])
            # The thread id is journaled before the model turn starts.  A crash
            # after this point leaves a durable RUNNING claim, so resume will
            # fail closed instead of issuing a duplicate turn.
            thread = self.codex.start_or_resume(row["codex_thread_id"], row["worktree"])
            self.journal.record_codex_thread(mission_id, thread, owner_pid, owner_start_ticks)
            turn = self.codex.turn(thread, guarded_prompt, row["worktree"])
            self.journal.complete_codex_turn(mission_id, turn.turn_id, owner_pid, owner_start_ticks)
            self.journal.event(mission_id, "codex_turn", {"thread_id": thread,
                                                            "turn_id": turn.turn_id,
                                                            "text": turn.text,
                                                            "forbidden_actions": list(forbidden_actions)})
            self.journal.db.commit()
            # The production adapter's exact-head contract requires a clean
            # committed worktree. Never advance a real mission into TEST with
            # uncheckpointed model edits; leave an explicit, resumable block so
            # a later owner turn can commit/reconcile instead of stranding TEST.
            if not isinstance(self.adapter, SimulatedAdapter):
                dirty = subprocess.run(
                    ["git", "-C", row["worktree"], "status", "--porcelain=v1",
                     "--untracked-files=all"],
                    text=True, capture_output=True, check=False,
                )
                if dirty.returncode != 0 or dirty.stdout:
                    self.journal.transition(
                        mission_id, State.BLOCKED_EXTERNAL,
                        "Codex turn did not leave a clean committed worktree; "
                        "checkpoint required before canonical validation",
                    )
                    return False
            return True
        except Exception as exc:
            self.journal.fail_codex_turn(mission_id, str(exc), owner_pid, owner_start_ticks)
            self.journal.transition(mission_id, State.BLOCKED_EXTERNAL,
                                    f"Codex turn failed closed: {exc}")
            return False

    def step(self, mission_id: str, spec: MissionSpec) -> State:
        persisted_spec = self.journal.spec(mission_id)
        if spec != persisted_spec:
            raise RuntimeError("runtime mission spec differs from the persisted mission contract")
        spec = persisted_spec
        self.reconcile(mission_id)
        row = self.journal.mission(mission_id)
        state = State(row["current_state"])
        expected_head = row["current_head"]

        def advance(target: State, reason: str) -> None:
            # Every decision in this step is bound to the state/HEAD snapshot
            # reconciled above.  A concurrent controller that changes either
            # value wins; this stale decision then fails its journal CAS.
            self.journal.transition(
                mission_id, target, reason,
                expected_state=state, expected_head=expected_head,
            )

        if state in TERMINAL:
            return state
        if self.journal.status(mission_id).background_jobs:
            return state  # a running owned process is pending, never terminal or duplicate work
        if state == State.CREATED:
            advance(State.PREPARING, "mission accepted")
        elif state == State.PREPARING:
            advance(State.IMPLEMENT, "worktree prepared")
        elif state == State.IMPLEMENT:
            if not permitted("source_edit", spec.forbidden_actions):
                advance(State.BLOCKED_POLICY, "mission forbids source_edit")
                return State.BLOCKED_POLICY
            if self._agent_turn(mission_id,
                                f"Continue mission objective: {spec.objective}. Inspect actual gates; do not declare terminal state from prose.",
                                spec.forbidden_actions):
                advance(State.TEST, "primary turn completed")
            return State(self.journal.mission(mission_id)["current_state"])
        elif state == State.TEST:
            for gate in spec.required_gates:
                if not permitted(f"gate:{gate}", spec.forbidden_actions):
                    advance(State.BLOCKED_POLICY, f"mission forbids gate:{gate}")
                    return State.BLOCKED_POLICY
                if not self.journal.gate_passed_at_head(mission_id, gate, row["current_head"]):
                    self.journal.update(mission_id, pending_gate=gate)
                    self.process.start(mission_id, gate, self.adapter.gate_argv(gate), row["worktree"], docker_env(mission_id), row["current_head"])
                    return state
            advance(State.REVIEW, "local canonical gates pass")
        elif state == State.REVIEW:
            head = row["current_head"]
            valid = self.journal.valid_reviews(mission_id, head)
            for reviewer in spec.reviews:
                if reviewer not in valid:
                    result: GateResult = self.adapter.review(reviewer, head)
                    self.journal.record_receipt(mission_id, reviewer, head, result.status)
                    if result.status == "BLOCKED_EXTERNAL":
                        advance(State.BLOCKED_EXTERNAL, result.evidence)
                        return State.BLOCKED_EXTERNAL
                    if result.status == "PENDING":
                        self.journal.update(mission_id, pending_gate=f"review:{reviewer}", ci_state="PENDING")
                        return state
                    if result.status != "PASS":
                        if self._agent_turn(mission_id, f"Repair reviewer {reviewer} findings: {result.evidence}",
                                            spec.forbidden_actions):
                            advance(State.IMPLEMENT, "review finding is auto-remediable")
                            return State.IMPLEMENT
                        return State(self.journal.mission(mission_id)["current_state"])
                    self.journal.update(mission_id, pending_gate=None, ci_state=None)
                    return state
            advance(State.CI, "all exact-head reviews pass")
        elif state == State.CI:
            result = self.adapter.ci(row["worktree"], row["current_head"])
            if result.status == "PASS":
                self.journal.update(mission_id, pending_gate=None, ci_state=None)
                advance(State.MERGE, "canonical CI pass")
            elif result.status == "FAIL":
                if self._agent_turn(mission_id, f"Repair canonical CI failure: {result.evidence}",
                                    spec.forbidden_actions):
                    advance(State.IMPLEMENT, "CI failure is auto-remediable")
            elif result.status == "BLOCKED_EXTERNAL":
                advance(State.BLOCKED_EXTERNAL, result.evidence)
            else:
                self.journal.update(mission_id, pending_gate="github-ci", ci_state=result.status)
        elif state == State.MERGE:
            if "merge" in spec.forbidden_actions:
                advance(State.BLOCKED_POLICY, "mission forbids merge")
                return State.BLOCKED_POLICY
            # Re-read canonical Git immediately before a durable one-owner claim.
            if self.adapter.exact_head(row["worktree"]) != row["current_head"]:
                self.reconcile(mission_id)
                return State(self.journal.mission(mission_id)["current_state"])
            if row["merge_claim_head"] is not None:
                status = self.adapter.merge_status(row["worktree"], row["merge_claim_head"])
                if status.status == "PASS":
                    advance(State.POST_MERGE, "canonical merge already completed")
                    return State.POST_MERGE
                if status.status != "NOT_STARTED":
                    advance(State.BLOCKED_EXTERNAL, status.evidence)
                    return State.BLOCKED_EXTERNAL
                reclaim = self.journal.reclaim_merge_claim_if_stale(mission_id, row["current_head"])
                if reclaim == "ACTIVE":
                    # A peer may be between its claim commit and its external
                    # merge call. Never erase or steal that live claim.
                    return State.MERGE
                if reclaim == "UNKNOWN":
                    advance(State.BLOCKED_EXTERNAL, "merge claim owner identity is unavailable")
                    return State.BLOCKED_EXTERNAL
                row = self.journal.mission(mission_id)
                # Canonical adapter proved the previous claim never started; reclaim
                # this exact HEAD in the same supervisor turn.
                owner_pid, owner_start_ticks = self._merge_owner()
                if not self.journal.claim_merge(mission_id, row["current_head"], owner_pid, owner_start_ticks):
                    return State.MERGE
                result = self.adapter.merge(row["worktree"], row["current_head"])
                if result.status != "PASS":
                    advance(State.BLOCKED_POLICY, result.evidence)
                else:
                    advance(State.POST_MERGE, result.evidence)
                return State(self.journal.mission(mission_id)["current_state"])
            if decide("merge", spec.merge_policy) == Decision.OWNER_APPROVAL_REQUIRED:
                if not self.journal.approved(mission_id, "merge", row["current_head"]):
                    self.journal.update(mission_id, approval_state="PENDING", pending_gate="owner-merge")
                    advance(State.WAITING_APPROVAL, "owner merge approval required")
                    return State.WAITING_APPROVAL
                self.journal.update(mission_id, approval_state="APPROVED", pending_gate=None)
                owner_pid, owner_start_ticks = self._merge_owner()
                if not self.journal.claim_merge(mission_id, row["current_head"], owner_pid, owner_start_ticks):
                    return State.MERGE
                result = self.adapter.merge(row["worktree"], row["current_head"])
                if result.status != "PASS":
                    advance(State.BLOCKED_POLICY, result.evidence)
                else:
                    advance(State.POST_MERGE, result.evidence)
            else:
                owner_pid, owner_start_ticks = self._merge_owner()
                if not self.journal.claim_merge(mission_id, row["current_head"], owner_pid, owner_start_ticks):
                    return State.MERGE
                result = self.adapter.merge(row["worktree"], row["current_head"])
                if result.status != "PASS":
                    advance(State.BLOCKED_POLICY, result.evidence)
                else:
                    advance(State.POST_MERGE, result.evidence)
        elif state == State.WAITING_APPROVAL:
            if self.journal.approved(mission_id, "merge", row["current_head"]):
                advance(State.MERGE, "persisted owner merge approval")
            else:
                return state
        elif state == State.POST_MERGE:
            for gate in spec.post_merge_gates:
                result = self.adapter.post_merge(gate, row["current_head"])
                if result.status != "PASS":
                    advance(State.BLOCKED_EXTERNAL, result.evidence)
                    return State.BLOCKED_EXTERNAL
            advance(State.DELIVER, "post merge gates pass")
        elif state == State.DELIVER:
            advance(State.PASS, "terminal acceptance conditions verified")
        return State(self.journal.mission(mission_id)["current_state"])

    def run_until_wait(self, mission_id: str, spec: MissionSpec, limit: int = 50) -> State:
        for _ in range(limit):
            before = self.journal.status(mission_id)
            after = self.step(mission_id, spec)
            row = self.journal.mission(mission_id)
            active_turn = row["codex_turn_state"] == "RUNNING"
            pending_review = after == State.REVIEW and str(row["pending_gate"] or "").startswith("review:")
            if after in TERMINAL or after in {State.BLOCKED_EXTERNAL, State.BLOCKED_POLICY} or self.journal.status(mission_id).background_jobs or (
                    before.state == after and after in {State.CI, State.MERGE, State.WAITING_APPROVAL}
                    ) or pending_review or (before.state == after and after in {State.IMPLEMENT, State.REVIEW, State.CI}
                                            and active_turn):
                return after
        raise RuntimeError("supervisor progress limit reached")

    def run_until_terminal(self, mission_id: str, spec: MissionSpec, limit: int = 100) -> State:
        """Keep this controller alive long enough to journal owned child exits."""
        for _ in range(limit):
            state = self.run_until_wait(mission_id, spec)
            if state in TERMINAL or state in {State.WAITING_APPROVAL, State.BLOCKED_EXTERNAL, State.BLOCKED_POLICY}:
                return state
            status = self.journal.status(mission_id)
            if status.background_jobs:
                if not self.process.wait_for_mission(mission_id):
                    # A process owned by a previous controller cannot be waited
                    # by this one; reconciliation remains the only safe truth.
                    return state
                self.collect_jobs(mission_id)
                continue
            if state == State.IMPLEMENT and self.journal.mission(mission_id)["codex_turn_state"] == "RUNNING":
                return state
            if state in {State.REVIEW, State.CI} and self.journal.mission(mission_id)["codex_turn_state"] == "RUNNING":
                return state
            if state == State.REVIEW and str(self.journal.mission(mission_id)["pending_gate"] or "").startswith("review:"):
                return state
            if state in {State.CI, State.MERGE}:
                return state
        raise RuntimeError("supervisor terminal progress limit reached")

    def collect_jobs(self, mission_id: str) -> None:
        self.reconcile(mission_id)

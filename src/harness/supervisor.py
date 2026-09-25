from __future__ import annotations

import inspect
import json
import math
import os
import re
import stat
import subprocess
import time
from pathlib import Path

from .adapters import GateResult, SimulatedAdapter
from .codex import CodexAdapter
from .domain import MissionSpec, State, TERMINAL
from .isolation import docker_env
from .journal import Journal
from .policy import Decision, decide, permitted
from .process import ProcessSupervisor
from .sandbox import SandboxUnavailable


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

    @staticmethod
    def _invoke_pr_adapter(method, worktree: str, head: str,
                           pr_number: int | None, pr_repo: str | None,
                           base_sha: str | None = None,
                           pr_base_sha: str | None = None):
        """Support legacy and current signatures without positional-arity guesses."""
        parameters = inspect.signature(method).parameters
        positional = [worktree, head]
        keywords = {}
        accepts_extra_keywords = any(p.kind == inspect.Parameter.VAR_KEYWORD
                                     for p in parameters.values())
        for name, value in (("pr_number", pr_number), ("pr_repo", pr_repo),
                            ("base_sha", base_sha), ("pr_base_sha", pr_base_sha)):
            parameter = parameters.get(name)
            if parameter is not None and parameter.kind == inspect.Parameter.POSITIONAL_ONLY:
                positional.append(value)
            elif parameter is not None or accepts_extra_keywords:
                keywords[name] = value
        return method(*positional, **keywords)

    @staticmethod
    def _invoke_gate_argv(method, gate: str, **context):
        parameters = inspect.signature(method).parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
            return method(gate, **context)
        accepted = {name: value for name, value in context.items() if name in parameters}
        return method(gate, **accepted)

    def _codex_checkpoint_ready(self, mission_id: str, worktree: str, *,
                                expected_state: State, expected_head: str | None) -> bool:
        """Require production Codex turns to leave only committed source state."""
        if isinstance(self.adapter, SimulatedAdapter):
            return True
        try:
            dirty = subprocess.run(
                ["git", "-C", worktree, "status", "--porcelain=v1",
                 "--untracked-files=all"],
                text=True, capture_output=True, check=False,
            )
        except OSError as exc:
            self.journal.transition(
                mission_id, State.BLOCKED_EXTERNAL,
                f"cannot inspect Codex worktree checkpoint: {exc}",
                expected_state=expected_state, expected_head=expected_head,
            )
            return False
        if dirty.returncode != 0 or dirty.stdout:
            self.journal.transition(
                mission_id, State.BLOCKED_EXTERNAL,
                "Codex turn did not leave a clean committed worktree; "
                "checkpoint required before canonical validation",
                expected_state=expected_state, expected_head=expected_head,
            )
            return False
        return True

    def reconcile(self, mission_id: str) -> None:
        def reconcile_transition(target: State, reason: str, snapshot) -> None:
            """Publish a polled-process decision only against its fresh snapshot.

            Reconciliation can race another controller's HEAD/state update.  The
            journal CAS is the authority; never let an old child-exit result
            overwrite a newer source identity or state.
            """
            self.journal.transition(
                mission_id,
                target,
                reason,
                expected_state=State(snapshot["current_state"]),
                expected_head=snapshot["current_head"],
            )

        row = self.journal.mission(mission_id)
        head = self.adapter.exact_head(row["worktree"])
        if head != row["current_head"]:
            # One transaction makes a crash observe either the old accepted HEAD or
            # a fully reopened mission; SQLite cache can never accept a hybrid.
            self.journal.reconcile_head(mission_id, head)
        for result in self.process.poll(mission_id):
            if result.state == "RUNNING":
                continue
            snapshot = self.journal.mission(mission_id)
            current = self.adapter.exact_head(snapshot["worktree"])
            if current != snapshot["current_head"]:
                self.journal.reconcile_head(mission_id, current)
                snapshot = self.journal.mission(mission_id)
            if (result.state in {"EXITED", "LOST"}
                    and self.journal.retire_unactionable_review_job(
                        mission_id, result.job_id, current,
                    )):
                continue
            if result.launch_head != current:
                if result.state == "EXITED" and result.exit_code != 0:
                    kind = "gate_failure_stale"
                elif result.state == "EXITED":
                    kind = "gate_stale"
                else:
                    kind = "process_result_stale"
                self.journal.event(mission_id, kind, {
                    "job_id": result.job_id,
                    "gate": snapshot["pending_gate"],
                    "state": result.state,
                    "launch_head": result.launch_head,
                    "current_head": current,
                    "exit_code": result.exit_code,
                })
                continue
            job = self.journal.db.execute("SELECT name,stdout_path FROM jobs WHERE job_id=?", (result.job_id,)).fetchone()
            if job and str(job["name"]).startswith("review:"):
                reviewer = str(job["name"]).split(":", 1)[1]
                spec = self.journal.spec(mission_id)
                scope = spec.mission_scope_file
                if result.state in {"EXITED", "LOST"}:
                    root = Path(snapshot["worktree"]).resolve()
                    try:
                        if not scope:
                            raise ValueError("FootballPrediction review requires mission_scope_file")
                        scope_path = (root / scope).resolve()
                        relative_scope = scope_path.relative_to(root)
                        tracked = subprocess.run(
                            ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", str(relative_scope)],
                            capture_output=True, text=True, check=False,
                        )
                        if not scope_path.is_file() or tracked.returncode != 0:
                            raise ValueError("mission scope contract is not a tracked file")
                        evidence_dir = self.adapter.review_evidence_dir(
                            snapshot["worktree"], mission_id, reviewer, current,
                        )
                        reviewed = self.adapter.review_result(
                            reviewer, worktree=snapshot["worktree"], base=snapshot["base_sha"], head=current,
                            mission_id=mission_id, scope_file=str(scope_path),
                            stdout_path=job["stdout_path"], evidence_dir=str(evidence_dir),
                        )
                    except Exception as exc:
                        reviewed = GateResult(
                            "BLOCKED_EXTERNAL", f"canonical review receipt validation failed: {exc}",
                        )
                    if reviewed.status == "BLOCKED_EXTERNAL":
                        # The process is conclusively terminal, so an
                        # incomplete or rejected receipt can be retried safely.
                        # A valid PASS/FAIL is consumed above; no second review
                        # may replace that terminal finding after restart.
                        self.journal.complete_review_job(
                            mission_id, result.job_id, reviewer, current,
                            "RETRY", reviewed.artifact, reviewed.evidence or
                            "canonical review writer exited without a durable receipt",
                            retry=True,
                        )
                        continue
                    details = reviewed.data if isinstance(reviewed.data, dict) else {}
                    reason = reviewed.evidence
                    if reviewed.status == "FAIL":
                        reason = "canonical review findings: " + json.dumps({
                            "reviewer": reviewer, "head": current,
                            "findings": details.get("findings", []),
                            "evidence": reviewed.evidence,
                        }, sort_keys=True)
                    consumed = self.journal.complete_review_job(
                        mission_id, result.job_id, reviewer, current, reviewed.status,
                        reviewed.artifact, reason,
                    )
                    if consumed and reviewed.status == "FAIL":
                        # The atomic journal method already moved the mission
                        # to IMPLEMENT; no second transition can race it.
                        pass
                    continue
            if result.state == "EXITED" and result.exit_code == 0:
                pending = snapshot["pending_gate"]
                if pending:
                    self.journal.complete_gate(mission_id, pending, current)
            elif result.state == "LOST":
                # Canonical validation commands are idempotent: resume retries an unobserved outcome.
                self.journal.event(mission_id, "process_retry_required", {"job_id": result.job_id})
            elif result.state == "EXITED" and result.exit_code != 0:
                pending = snapshot["pending_gate"]
                if pending and State(snapshot["current_state"]) == State.TEST:
                    self.journal.event(mission_id, "gate_failed_auto_repair", {"gate": pending, "exit_code": result.exit_code})
                    reconcile_transition(
                        State.IMPLEMENT,
                        f"canonical gate {pending} failed; repair required",
                        snapshot,
                    )
                else:
                    reconcile_transition(
                        State.FAILED_FATAL,
                        f"owned process {result.state}: {result.exit_code}",
                        snapshot,
                    )
            else:
                reconcile_transition(
                    State.FAILED_FATAL,
                    f"owned process {result.state}: {result.exit_code}",
                    snapshot,
                )

    def _agent_turn(self, mission_id: str, prompt: str, forbidden_actions: tuple[str, ...]) -> bool:
        owner_pid, owner_start_ticks = self._merge_owner()
        source = self.journal.mission(mission_id)
        expected_state = State(source["current_state"])
        expected_head = source["current_head"]
        claim = self.journal.claim_codex_turn(mission_id, owner_pid, owner_start_ticks)
        if claim == "ACTIVE":
            return False
        if claim == "UNKNOWN":
            self.journal.transition(mission_id, State.BLOCKED_EXTERNAL,
                                    "previous Codex turn outcome is unknown after owner loss",
                                    expected_state=expected_state,
                                    expected_head=expected_head)
            return False
        if claim == "STALE":
            if self.journal.discard_stale_codex_turn(
                    mission_id, expected_state=expected_state,
                    expected_head=expected_head):
                # Retire the obsolete completion in its own durable step.  A
                # subsequent controller iteration may claim a fresh turn for
                # the current exact source snapshot.
                return False
            self.journal.transition(
                mission_id, State.BLOCKED_EXTERNAL,
                "stale Codex turn lacks a safely discardable completion identity",
                expected_state=expected_state, expected_head=expected_head,
            )
            return False
        if claim == "COMPLETED":
            # A previous controller durably observed completion but crashed
            # before publishing the state transition.  The caller consumes
            # this marker atomically with that transition; never invoke Codex
            # a second time for the same mission turn.
            row = self.journal.mission(mission_id)
            return self._codex_checkpoint_ready(
                mission_id, row["worktree"],
                expected_state=expected_state, expected_head=expected_head,
            )
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
            # Check both freshly completed and crash-recovered durable turns.
            # Otherwise a restart could consume COMPLETED and bypass the
            # production adapter's committed-worktree boundary.
            return self._codex_checkpoint_ready(
                mission_id, row["worktree"],
                expected_state=expected_state, expected_head=expected_head,
            )
        except Exception as exc:
            self.journal.fail_codex_turn(mission_id, str(exc), owner_pid, owner_start_ticks)
            self.journal.transition(mission_id, State.BLOCKED_EXTERNAL,
                                    f"Codex turn failed closed: {exc}",
                                    expected_state=expected_state,
                                    expected_head=expected_head)
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

        def finish_merge(result: GateResult) -> State:
            """Classify merge outcomes without treating provider failure as policy denial."""
            if result.status == "PASS":
                data = result.data if isinstance(result.data, dict) else {}
                identity = self.journal.mission(mission_id)
                expected_pr = identity["merge_claim_pr_number"] or identity["pr_number"]
                expected_repo = identity["merge_claim_pr_repo"] or identity["pr_repo"]
                expected_pr_base = identity["merge_claim_pr_base_sha"] or identity["pr_base_sha"]
                if not data.get("pr") or not data.get("merge_sha"):
                    if not isinstance(self.adapter, SimulatedAdapter):
                        advance(State.BLOCKED_EXTERNAL, "merge PASS omitted PR or merge SHA")
                        return State.BLOCKED_EXTERNAL
                elif (not isinstance(data.get("pr"), int) or isinstance(data.get("pr"), bool)
                      or data.get("pr") != expected_pr or data.get("repo") != expected_repo
                      or data.get("pr_base_sha") != expected_pr_base):
                    advance(State.BLOCKED_EXTERNAL, "merge PASS changed the durable PR/reviewed-base identity")
                    return State.BLOCKED_EXTERNAL
                merge_sha = data.get("merge_sha")
                if merge_sha is not None and (not isinstance(merge_sha, str)
                        or len(merge_sha) != 40 or any(ch not in "0123456789abcdef" for ch in merge_sha.lower())):
                    advance(State.BLOCKED_EXTERNAL, "merge PASS omitted a valid full merge SHA")
                    return State.BLOCKED_EXTERNAL
                if not expected_pr or not expected_repo:
                    advance(State.BLOCKED_EXTERNAL, "merge claim has no durable PR identity")
                    return State.BLOCKED_EXTERNAL
                self.journal.complete_merge(
                    mission_id, expected_head, pr_number=expected_pr,
                    pr_repo=expected_repo, pr_base_sha=expected_pr_base,
                    merge_sha=merge_sha,
                    reason=result.evidence,
                )
            elif result.status == "BLOCKED_POLICY":
                advance(State.BLOCKED_POLICY, result.evidence)
            else:
                # External/transient/unknown merge outcomes are never silently
                # accepted and must not be mislabeled as a policy decision.
                advance(State.BLOCKED_EXTERNAL, result.evidence or
                        f"merge returned unsupported status: {result.status}")
            return State(self.journal.mission(mission_id)["current_state"])

        def execute_claimed_merge(worktree: str, head: str) -> State:
            """Execute once after a durable claim; unknown outcomes remain reconcilable."""
            def reconcile_unknown(reason: str) -> State:
                # Publish the uncertainty before querying canonical GitHub
                # state.  A controller death during this query leaves an
                # armed claim that a fresh controller can reconcile, but can
                # never safely re-invoke the merge.
                self.journal.update(mission_id, pending_gate="merge-outcome-unknown")
                try:
                    status = self._invoke_pr_adapter(
                        self.adapter.merge_status, worktree, head,
                        self.journal.mission(mission_id)["merge_claim_pr_number"],
                        self.journal.mission(mission_id)["merge_claim_pr_repo"],
                        pr_base_sha=self.journal.mission(mission_id)["merge_claim_pr_base_sha"],
                    )
                except Exception as exc:
                    advance(State.BLOCKED_EXTERNAL,
                            f"cannot reconcile ambiguous merge outcome: {reason}; {exc}")
                    return State.BLOCKED_EXTERNAL
                if status.status == "PASS":
                    return finish_merge(status)
                advance(State.BLOCKED_EXTERNAL,
                        status.evidence or f"ambiguous merge outcome: {reason}")
                return State.BLOCKED_EXTERNAL

            try:
                identity = self.journal.mission(mission_id)
                claimed_pr = identity["merge_claim_pr_number"]
                claimed_repo = identity["merge_claim_pr_repo"]
                owner_pid, owner_ticks = self._merge_owner()
                # Re-check the exact live recovery lease immediately before
                # the irreversible adapter call. mark_merge_invocation_started
                # repeats the owner/HEAD check while atomically arming the
                # one-shot invocation, closing any race after this assertion.
                retry_safety = self.journal.confirm_merge_retry_safe(
                    mission_id, head, owner_pid, owner_ticks,
                )
                if retry_safety != "RETRY_SAFE":
                    return State(self.journal.mission(mission_id)["current_state"])
                if not self.journal.mark_merge_invocation_started(
                        mission_id, head, owner_pid, owner_ticks):
                    return State(self.journal.mission(mission_id)["current_state"])
                result = self._invoke_pr_adapter(
                    self.adapter.merge, worktree, head, claimed_pr, claimed_repo,
                    pr_base_sha=identity["merge_claim_pr_base_sha"],
                )
            except Exception as exc:
                self.journal.event(mission_id, "merge_outcome_unknown", {"head": head, "error": str(exc)})
                self.journal.db.commit()
                return reconcile_unknown(f"merge invocation failed: {exc}")
            if result.status == "BLOCKED_EXTERNAL":
                self.journal.event(mission_id, "merge_outcome_unknown", {"head": head, "error": result.evidence})
                self.journal.db.commit()
                return reconcile_unknown(result.evidence or "merge outcome is ambiguous after invocation")
            self.journal.update(mission_id, pending_gate=None)
            return finish_merge(result)

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
            prompt = f"Continue mission objective: {spec.objective}. Inspect actual gates; do not declare terminal state from prose."
            repair_context = self._async_review_repair_context(mission_id, expected_head)
            if repair_context:
                prompt += (
                    "\n\nA canonical asynchronous review failed for this exact HEAD. "
                    "Treat the following JSON as reviewer evidence to verify against source, "
                    "then repair the confirmed findings and preserve the mission safety policy:\n"
                    + repair_context
                )
            if self._agent_turn(mission_id, prompt,
                                spec.forbidden_actions):
                self.journal.transition_after_codex_turn(
                    mission_id, State.TEST, "primary turn completed",
                    expected_state=state, expected_head=expected_head,
                )
            return State(self.journal.mission(mission_id)["current_state"])
        elif state == State.TEST:
            for gate in spec.required_gates:
                if not permitted(f"gate:{gate}", spec.forbidden_actions):
                    advance(State.BLOCKED_POLICY, f"mission forbids gate:{gate}")
                    return State.BLOCKED_POLICY
                if not self.journal.gate_passed_at_head(mission_id, gate, row["current_head"]):
                    gate_env = {}
                    prepare = getattr(self.adapter, "prepare_gate", None)
                    if callable(prepare) and not isinstance(self.adapter, SimulatedAdapter):
                        try:
                            prepared = prepare(
                                gate, worktree=row["worktree"], base=row["base_sha"],
                                head=row["current_head"], mission_id=mission_id,
                                scope_file=str((Path(row["worktree"]) / spec.mission_scope_file).resolve())
                                if spec.mission_scope_file else "",
                            )
                        except Exception as exc:
                            prepared = GateResult("BLOCKED_EXTERNAL", f"canonical gate input preparation failed: {exc}")
                        if prepared.status == "PENDING":
                            self.journal.update(mission_id, pending_gate=gate, ci_state="PENDING")
                            return state
                        if prepared.status == "BLOCKED_EXTERNAL":
                            details = prepared.data if isinstance(prepared.data, dict) else {}
                            if details.get("retryable"):
                                self.journal.update(mission_id, pending_gate=gate, ci_state="PENDING")
                                return state
                            advance(State.BLOCKED_EXTERNAL, prepared.evidence)
                            return State.BLOCKED_EXTERNAL
                        if prepared.status != "PASS":
                            advance(State.BLOCKED_EXTERNAL, prepared.evidence or "gate input preparation failed")
                            return State.BLOCKED_EXTERNAL
                        gate_env = (prepared.data or {}).get("env", {}) if isinstance(prepared.data, dict) else {}
                    self.journal.update(mission_id, pending_gate=gate)
                    env = docker_env(mission_id)
                    if isinstance(gate_env, dict):
                        env.update({str(key): str(value) for key, value in gate_env.items()})
                    try:
                        self.process.start(
                            mission_id, gate,
                            self._invoke_gate_argv(self.adapter.gate_argv, gate,
                                worktree=row["worktree"], base=row["base_sha"],
                                head=row["current_head"], mission_id=mission_id,
                                scope_file=spec.mission_scope_file or "",
                            ),
                            row["worktree"], env, row["current_head"],
                            sandbox_profile=(None if isinstance(self.adapter, SimulatedAdapter)
                                            else "project-gate"),
                        )
                    except SandboxUnavailable as exc:
                        advance(State.BLOCKED_EXTERNAL, f"candidate gate isolation unavailable: {exc}")
                        return State.BLOCKED_EXTERNAL
                    return state
            advance(State.REVIEW, "local canonical gates pass")
        elif state == State.REVIEW:
            head = row["current_head"]
            valid = self.journal.valid_reviews(mission_id, head)
            for reviewer in spec.reviews:
                if reviewer not in valid:
                    if not permitted(f"review:{reviewer}", spec.forbidden_actions):
                        advance(State.BLOCKED_POLICY, f"mission forbids review:{reviewer}")
                        return State.BLOCKED_POLICY
                    if not isinstance(self.adapter, SimulatedAdapter):
                        if not spec.mission_scope_file:
                            advance(State.BLOCKED_EXTERNAL, "FootballPrediction review requires mission_scope_file")
                            return State.BLOCKED_EXTERNAL
                        root = Path(row["worktree"]).resolve()
                        scope = (root / spec.mission_scope_file).resolve()
                        tracked = subprocess.run(["git", "-C", str(root), "ls-files", "--error-unmatch", "--", str(scope.relative_to(root))], capture_output=True, text=True, check=False) if root in scope.parents else None
                        if not scope.is_file() or tracked is None or tracked.returncode != 0:
                            advance(State.BLOCKED_EXTERNAL, f"mission scope contract is unavailable: {scope}")
                            return State.BLOCKED_EXTERNAL
                        preflight = self.adapter.review_preflight(row["worktree"], row["base_sha"], head)
                        if preflight.status != "PASS":
                            advance(State.BLOCKED_EXTERNAL, preflight.evidence)
                            return State.BLOCKED_EXTERNAL
                        try:
                            evidence = self.adapter.review_evidence_dir(
                                row["worktree"], mission_id, reviewer, head,
                            )
                            evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
                            for private_dir in (evidence.parents[2], evidence.parents[1],
                                                evidence.parents[0], evidence):
                                if private_dir.is_symlink():
                                    raise RuntimeError(f"review evidence directory is a symlink: {private_dir}")
                                private_dir.chmod(0o700)
                                info = private_dir.lstat()
                                if ((hasattr(os, "getuid") and info.st_uid != os.getuid())
                                        or stat.S_IMODE(info.st_mode) & 0o077):
                                    raise RuntimeError(f"review evidence directory is not private: {private_dir}")
                            argv = self.adapter.review_argv(
                                reviewer, worktree=row["worktree"], base=row["base_sha"], head=head,
                                mission_id=mission_id, scope_file=str(scope), evidence_dir=str(evidence),
                            )
                            self.journal.update(mission_id, pending_gate=f"review:{reviewer}")
                            self.process.start(
                                mission_id, f"review:{reviewer}", argv,
                                row["worktree"], docker_env(mission_id), head,
                            )
                        except Exception as exc:
                            advance(State.BLOCKED_EXTERNAL,
                                    f"canonical reviewer could not start safely: {exc}")
                            return State.BLOCKED_EXTERNAL
                        return state
                    result: GateResult = self.adapter.review(reviewer, head)
                    self.journal.record_receipt(mission_id, reviewer, head, result.status)
                    if result.status == "BLOCKED_EXTERNAL":
                        advance(State.BLOCKED_EXTERNAL, result.evidence)
                        return State.BLOCKED_EXTERNAL
                    if result.status == "PENDING":
                        self.journal.update(mission_id, pending_gate=f"review:{reviewer}", ci_state="PENDING")
                        return state
                    if result.status != "PASS":
                        if not permitted("source_edit", spec.forbidden_actions):
                            advance(State.BLOCKED_POLICY,
                                    "mission forbids source-edit repair for review findings")
                            return State.BLOCKED_POLICY
                        if self._agent_turn(mission_id, f"Repair reviewer {reviewer} findings: {result.evidence}",
                                            spec.forbidden_actions):
                            self.journal.transition_after_codex_turn(
                                mission_id, State.IMPLEMENT,
                                "review finding is auto-remediable",
                                expected_state=state, expected_head=expected_head,
                            )
                            return State.IMPLEMENT
                        return State(self.journal.mission(mission_id)["current_state"])
                    self.journal.update(mission_id, pending_gate=None, ci_state=None)
                    return state
            advance(State.CI, "all exact-head reviews pass")
        elif state == State.CI:
            result = self._invoke_pr_adapter(
                self.adapter.ci, row["worktree"], row["current_head"],
                row["pr_number"], row["pr_repo"], row["base_sha"], row["pr_base_sha"],
            )
            facts = result.data if isinstance(result.data, dict) else {}
            if result.status == "BLOCKED_EXTERNAL" and facts.get("retryable"):
                self.journal.update(mission_id, pending_gate="github-ci", ci_state="PENDING")
                return state
            if (not isinstance(result.data, dict)
                    and not isinstance(self.adapter, SimulatedAdapter)
                    and result.status in {"PASS", "PENDING", "FAIL"}):
                advance(State.BLOCKED_EXTERNAL, "canonical CI returned malformed PR identity evidence")
                return State.BLOCKED_EXTERNAL
            if (not isinstance(self.adapter, SimulatedAdapter)
                    and ("pr_number" not in facts or "pr_repo" not in facts)):
                advance(State.BLOCKED_EXTERNAL, "canonical CI omitted durable PR identity evidence")
                return State.BLOCKED_EXTERNAL
            if "pr_number" in facts or "pr_repo" in facts:
                pr_number, pr_repo = facts.get("pr_number"), facts.get("pr_repo")
                pr_base_sha = facts.get("pr_base_sha")
                if (not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0
                        or not isinstance(pr_repo, str)
                        or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pr_repo) is None
                        or not isinstance(pr_base_sha, str)
                        or re.fullmatch(r"[0-9a-fA-F]{40}", pr_base_sha) is None):
                    advance(State.BLOCKED_EXTERNAL, "canonical CI returned invalid durable PR identity")
                    return State.BLOCKED_EXTERNAL
                if not self.journal.bind_pr_identity(
                        mission_id, row["current_head"], pr_number, pr_repo, pr_base_sha):
                    advance(State.BLOCKED_EXTERNAL, "CI PR identity changed or lost its exact source snapshot")
                    return State.BLOCKED_EXTERNAL
            if result.status == "PASS":
                self.journal.update(mission_id, pending_gate=None, ci_state=None)
                advance(State.MERGE, "canonical CI pass")
            elif result.status == "FAIL":
                if not permitted("source_edit", spec.forbidden_actions):
                    advance(State.BLOCKED_POLICY,
                            "mission forbids source-edit repair for CI failure")
                    return State.BLOCKED_POLICY
                if self._agent_turn(mission_id, f"Repair canonical CI failure: {result.evidence}",
                                    spec.forbidden_actions):
                    self.journal.transition_after_codex_turn(
                        mission_id, State.IMPLEMENT, "CI failure is auto-remediable",
                        expected_state=state, expected_head=expected_head,
                    )
            elif result.status == "BLOCKED_EXTERNAL":
                details = result.data if isinstance(result.data, dict) else {}
                if details.get("retryable"):
                    self.journal.update(mission_id, pending_gate="github-ci", ci_state="PENDING")
                else:
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
            if row["pr_number"] is None:
                pr = self.adapter.discover_pr(row["worktree"], row["current_head"])
                if pr.status != "PASS":
                    if isinstance(pr.data, dict) and pr.data.get("retryable"):
                        self.journal.update(mission_id, pending_gate="pr-discovery", ci_state="PENDING")
                        return state
                    advance(State.BLOCKED_EXTERNAL, pr.evidence)
                    return State.BLOCKED_EXTERNAL
                facts = pr.data if isinstance(pr.data, dict) else {}
                pr_number, pr_repo = facts.get("number"), facts.get("repo")
                if (not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0
                        or not isinstance(pr_repo, str)
                        or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pr_repo) is None):
                    advance(State.BLOCKED_EXTERNAL,
                            "PR discovery returned an invalid durable PR identity")
                    return State.BLOCKED_EXTERNAL
                pr_base_sha = facts.get("base_sha")
                if (not isinstance(pr_base_sha, str)
                        or re.fullmatch(r"[0-9a-fA-F]{40}", pr_base_sha) is None
                        or not self.journal.bind_pr_identity(
                            mission_id, row["current_head"], pr_number, pr_repo, pr_base_sha)):
                    advance(State.BLOCKED_EXTERNAL, "PR discovery omitted or changed exact base SHA")
                    return State.BLOCKED_EXTERNAL
                row = self.journal.mission(mission_id)
            if row["merge_claim_head"] is not None:
                claim_head = row["merge_claim_head"]
                owner_pid, owner_start_ticks = self._merge_owner()
                recovery = self.journal.claim_merge_recovery(
                    mission_id, claim_head, owner_pid, owner_start_ticks,
                )
                resume_owned_pending_ci = False
                if recovery == "ACTIVE":
                    # The same still-running controller may resume its own
                    # uninvoked claim after pre-merge CI returned PENDING.
                    # Every other live claim remains strictly non-stealable.
                    if (row["merge_claim_pid"] == owner_pid
                            and row["merge_claim_start_ticks"] == owner_start_ticks
                            and row["merge_invocation_started"] == 0
                            and row["pending_gate"] == "pre-merge-ci"
                            and claim_head == row["current_head"]):
                        resume_owned_pending_ci = True
                        row = self.journal.mission(mission_id)
                    else:
                        return State.MERGE
                if recovery == "UNKNOWN":
                    advance(State.BLOCKED_EXTERNAL, "merge claim owner identity is unavailable")
                    return State.BLOCKED_EXTERNAL
                if not resume_owned_pending_ci and recovery != "RECOVERY_CLAIMED":
                    return State(self.journal.mission(mission_id)["current_state"])
                if not resume_owned_pending_ci:
                    row = self.journal.mission(mission_id)
                    invocation_uncertain = (bool(row["merge_invocation_started"])
                                            or row["pending_gate"] == "merge-outcome-unknown")
                    if invocation_uncertain:
                        try:
                            status = self._invoke_pr_adapter(
                                self.adapter.merge_status, row["worktree"], claim_head,
                                row["merge_claim_pr_number"], row["merge_claim_pr_repo"],
                                pr_base_sha=row["merge_claim_pr_base_sha"],
                            )
                        except Exception as exc:
                            advance(State.BLOCKED_EXTERNAL, f"cannot reconcile uncertain merge: {exc}")
                            return State.BLOCKED_EXTERNAL
                        if status.status == "PASS":
                            if claim_head != row["current_head"]:
                                advance(State.BLOCKED_EXTERNAL,
                                        "merge completed for a stale claimed HEAD after canonical HEAD drift")
                                return State.BLOCKED_EXTERNAL
                            return finish_merge(status)
                        advance(State.BLOCKED_EXTERNAL, status.evidence or
                                "merge invocation may have started; outcome remains ambiguous")
                        return State.BLOCKED_EXTERNAL
                    retry = self.journal.confirm_merge_retry_safe(
                        mission_id, claim_head, owner_pid, owner_start_ticks,
                    )
                    if retry == "UNKNOWN":
                        advance(State.BLOCKED_EXTERNAL, "merge recovery identity is unavailable")
                        return State.BLOCKED_EXTERNAL
                    if retry == "REWOUND_HEAD_DRIFT":
                        # The durable invocation phase proved the stale merge was
                        # never invoked. Rewind before any new merge claim.
                        reclaimed = self.journal.mission(mission_id)
                        if (State(reclaimed["current_state"]) != State.TEST or
                                reclaimed["merge_claim_head"] is not None):
                            advance(
                                State.BLOCKED_EXTERNAL,
                                "merge claim drift reclaim did not durably rewind to TEST",
                            )
                            return State.BLOCKED_EXTERNAL
                        return State(reclaimed["current_state"])
                    if retry != "RETRY_SAFE":
                        return State(self.journal.mission(mission_id)["current_state"])
                    self.journal.update(mission_id, pending_gate=None)
            technical = self._invoke_pr_adapter(
                self.adapter.ci, row["worktree"], row["current_head"],
                row["pr_number"], row["pr_repo"], row["base_sha"], row["pr_base_sha"],
            )
            if technical.status == "PENDING":
                self.journal.update(mission_id, pending_gate="pre-merge-ci", ci_state="PENDING")
                return state
            if technical.status == "BLOCKED_EXTERNAL" and isinstance(technical.data, dict) and technical.data.get("retryable"):
                self.journal.update(mission_id, pending_gate="pre-merge-ci", ci_state="PENDING")
                return state
            if technical.status != "PASS":
                advance(State.BLOCKED_EXTERNAL, technical.evidence or "pre-merge canonical CI recheck failed")
                return State.BLOCKED_EXTERNAL

            # Owner approval is a boundary, not a reporting detail.  Do not
            # invoke any target-controlled merge-readiness/preflight command
            # until the durable approval for this exact PR identity and HEAD
            # exists.  A waiting mission is resumed here after approval and
            # only then evaluates the canonical target gate.
            decision = decide("merge", spec.merge_policy)
            if decision == Decision.OWNER_APPROVAL_REQUIRED:
                if not self.journal.approved(mission_id, "merge", row["current_head"]):
                    if row["merge_claim_head"] is not None:
                        advance(State.BLOCKED_EXTERNAL,
                                "recovered unstarted merge claim has no current owner approval")
                        return State.BLOCKED_EXTERNAL
                    self.journal.update(mission_id, approval_state="PENDING", pending_gate="owner-merge")
                    advance(State.WAITING_APPROVAL, "owner merge approval required")
                    return State.WAITING_APPROVAL
                self.journal.update(mission_id, approval_state="APPROVED", pending_gate=None)
            elif decision != Decision.AUTO_CONTINUE:
                advance(State.BLOCKED_POLICY, "unknown merge policy decision; fail closed")
                return State.BLOCKED_POLICY

            if not isinstance(self.adapter, SimulatedAdapter):
                merge_ready = getattr(self.adapter, "merge_ready", None)
                if not callable(merge_ready) or not spec.mission_scope_file:
                    advance(State.BLOCKED_EXTERNAL, "target project canonical merge-readiness gate is unavailable")
                    return State.BLOCKED_EXTERNAL
                artifacts = self.journal.latest_review_artifacts(mission_id, row["current_head"])
                try:
                    readiness = merge_ready(
                        worktree=row["worktree"], base=row["base_sha"], head=row["current_head"],
                        mission_id=mission_id,
                        scope_file=str((Path(row["worktree"]) / spec.mission_scope_file).resolve()),
                        pr_number=row["pr_number"], pr_repo=row["pr_repo"],
                        pr_base_sha=row["pr_base_sha"],
                        receipts=artifacts, ci_status="PASS",
                    )
                except Exception as exc:
                    readiness = GateResult("BLOCKED_EXTERNAL", f"canonical merge-readiness invocation failed: {exc}")
                if readiness.status != "PASS":
                    advance(State.BLOCKED_EXTERNAL, readiness.evidence or "canonical merge-readiness rejected merge")
                    return State.BLOCKED_EXTERNAL
            if row["merge_claim_head"] is None:
                owner_pid, owner_start_ticks = self._merge_owner()
                if not self.journal.claim_merge(mission_id, row["current_head"], owner_pid, owner_start_ticks):
                    return State.MERGE
            execute_claimed_merge(row["worktree"], row["current_head"])
        elif state == State.WAITING_APPROVAL:
            if self.journal.approved(mission_id, "merge", row["current_head"]):
                advance(State.MERGE, "persisted owner merge approval")
            else:
                return state
        elif state == State.POST_MERGE:
            if not isinstance(self.adapter, SimulatedAdapter) and (not row["merge_sha"] or not row["pr_number"] or not row["pr_repo"]):
                advance(State.BLOCKED_EXTERNAL, "post-merge requires durable PR and merge SHA")
                return State.BLOCKED_EXTERNAL
            if not isinstance(self.adapter, SimulatedAdapter) and row["merge_sha"] and row["pr_number"]:
                production = self.adapter.post_merge(
                    row["worktree"], row["merge_sha"], row["pr_number"], row["pr_repo"], row["branch"], row["base_sha"],
                )
                if production.status == "PENDING":
                    self.journal.update(mission_id, pending_gate="production-gate", ci_state="PENDING")
                    return state
                if production.status != "PASS":
                    advance(State.BLOCKED_EXTERNAL, production.evidence)
                    return State.BLOCKED_EXTERNAL
                facts = production.data if isinstance(production.data, dict) else {}
                main_sha, tree_sha = facts.get("main_sha"), facts.get("tree_sha")
                observed_merge_sha = facts.get("ci_head_sha")
                full_sha = lambda value: (isinstance(value, str)
                                          and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None)
                if (not isinstance(production.data, dict)
                        or not full_sha(observed_merge_sha)
                        or observed_merge_sha.lower() != str(row["merge_sha"]).lower()
                        or not full_sha(main_sha) or not full_sha(tree_sha)):
                    advance(State.BLOCKED_EXTERNAL,
                            "Production Gate PASS omitted exact merge-SHA or full main/tree truth")
                    return State.BLOCKED_EXTERNAL
                self.journal.update(mission_id, main_sha=main_sha.lower(), tree_sha=tree_sha.lower(),
                                    pending_gate=None, ci_state=None)
            # Legacy simulation gates remain a test seam only. Production is
            # governed by the exact merge-SHA Production Gate above.
            if isinstance(self.adapter, SimulatedAdapter):
                for gate in spec.post_merge_gates:
                    result = self.adapter.post_merge(gate, row["current_head"])
                    if result.status != "PASS":
                        advance(State.BLOCKED_EXTERNAL, result.evidence)
                        return State.BLOCKED_EXTERNAL
            observed = self.adapter.exact_head(row["worktree"])
            if observed != row["current_head"]:
                self.journal.reconcile_head(mission_id, observed)
                return State(self.journal.mission(mission_id)["current_state"])
            advance(State.DELIVER, "post merge gates pass")
        elif state == State.DELIVER:
            observed = self.adapter.exact_head(row["worktree"])
            if observed != expected_head:
                self.journal.reconcile_head(mission_id, observed)
                return State(self.journal.mission(mission_id)["current_state"])
            advance(State.PASS, "terminal acceptance conditions verified")
        return State(self.journal.mission(mission_id)["current_state"])

    def run_until_wait(self, mission_id: str, spec: MissionSpec, limit: int = 50) -> State:
        for _ in range(limit):
            before = self.journal.status(mission_id)
            after = self.step(mission_id, spec)
            row = self.journal.mission(mission_id)
            active_turn = row["codex_turn_state"] == "RUNNING"
            pending_review = after == State.REVIEW and str(row["pending_gate"] or "").startswith("review:")
            pending_production = after == State.POST_MERGE and row["pending_gate"] == "production-gate"
            pending_external_gate = (after == State.TEST and row["pending_gate"] in spec.required_gates
                                     and row["ci_state"] == "PENDING")
            if after in TERMINAL or after in {State.BLOCKED_EXTERNAL, State.BLOCKED_POLICY} or self.journal.status(mission_id).background_jobs or (
                    before.state == after and after in {State.CI, State.MERGE, State.WAITING_APPROVAL}
                    ) or pending_review or pending_production or pending_external_gate or (before.state == after and after in {State.IMPLEMENT, State.REVIEW, State.CI}
                                            and active_turn):
                return after
        raise RuntimeError("supervisor progress limit reached")

    def run_until_terminal(self, mission_id: str, spec: MissionSpec, limit: int = 100,
                           poll_interval: float = 5.0) -> State:
        """Keep this controller alive long enough to journal owned child exits."""
        try:
            valid_poll_interval = (not isinstance(poll_interval, bool)
                                   and isinstance(poll_interval, (int, float))
                                   and math.isfinite(poll_interval) and poll_interval > 0)
        except (OverflowError, TypeError):
            valid_poll_interval = False
        if not valid_poll_interval:
            raise ValueError("poll_interval must be a finite positive number")
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
            row = self.journal.mission(mission_id)
            pending_ci = ((state == State.CI and row["pending_gate"] == "github-ci")
                          or (state == State.MERGE and row["pending_gate"] == "pre-merge-ci"))
            pending_production = (state == State.POST_MERGE
                                  and row["pending_gate"] == "production-gate")
            pending_pr_discovery = (state == State.MERGE
                                    and row["pending_gate"] == "pr-discovery")
            pending_external_gate = (state == State.TEST and row["pending_gate"] in spec.required_gates
                                     and row["ci_state"] == "PENDING")
            if pending_ci or pending_production or pending_external_gate or pending_pr_discovery:
                time.sleep(poll_interval)
                continue
            if state in {State.CI, State.MERGE, State.POST_MERGE}:
                return state
        row = self.journal.mission(mission_id)
        if ((State(row["current_state"]) == State.CI and row["pending_gate"] == "github-ci")
                or (State(row["current_state"]) == State.MERGE and row["pending_gate"] == "pre-merge-ci")
                or (State(row["current_state"]) == State.POST_MERGE
                    and row["pending_gate"] == "production-gate")
                or (State(row["current_state"]) == State.MERGE
                    and row["pending_gate"] == "pr-discovery")
                or (State(row["current_state"]) == State.TEST
                    and row["pending_gate"] in spec.required_gates
                    and row["ci_state"] == "PENDING")):
            return State(row["current_state"])
        raise RuntimeError("supervisor terminal progress limit reached")

    def collect_jobs(self, mission_id: str) -> None:
        self.reconcile(mission_id)

    def _async_review_repair_context(self, mission_id: str, head: str | None) -> str:
        row = self.journal.db.execute(
            "SELECT payload_json FROM events WHERE mission_id=? AND kind='state_transition' "
            "ORDER BY seq DESC LIMIT 1",
            (mission_id,),
        ).fetchone()
        if row is None:
            return ""
        try:
            payload = json.loads(row["payload_json"])
            if (payload.get("from") != State.REVIEW or payload.get("to") != State.IMPLEMENT
                    or payload.get("head") != head):
                return ""
            reason = payload.get("reason", "")
            marker = "canonical review findings: "
            if not isinstance(reason, str) or not reason.startswith(marker):
                return ""
            details = json.loads(reason[len(marker):])
            if not isinstance(details, dict) or details.get("head") != head:
                return ""
            return json.dumps(details, sort_keys=True, indent=2)
        except (TypeError, json.JSONDecodeError):
            return ""

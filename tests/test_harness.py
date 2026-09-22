from __future__ import annotations

import tempfile
import unittest
import json
import subprocess
from dataclasses import replace
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from harness.adapters import FootballPredictionAdapter, GateResult, SimulatedAdapter
from harness.cli import approval_head, build, load_spec, reconcile_supplied_spec
from harness.codex import AppServerCodex, FixtureCodex, Turn
from harness.domain import InvalidTransition, MissionSpec, State
from harness.isolation import WorktreeManager, compose_namespace, docker_env
from harness.journal import Journal
from harness.process import JobResult, ProcessSupervisor, proc_start_ticks
from harness.supervisor import Supervisor


class FakeCodex:
    def __init__(self, messages=None):
        self.thread = None
        self.turns = []
        self.messages = iter(messages or ["任务尚未完成。", "已完成。"])

    def start_or_resume(self, thread_id, cwd):
        self.thread = thread_id or "thread-1"
        return self.thread

    def turn(self, thread_id, prompt, cwd):
        value = next(self.messages, "已完成。")
        self.turns.append((thread_id, prompt, value))
        return Turn(thread_id, f"turn-{len(self.turns)}", value)


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.journal = Journal(root / "harness.sqlite")
        self.adapter = SimulatedAdapter()
        self.codex = FakeCodex()
        self.supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, root / "logs"), self.codex, self.adapter)
        self.spec = MissionSpec("safe-demo", "/safe/repo", "harmless fixture", adapter="simulation", merge_policy="auto")
        self.worktree = root / "safe-worktree"
        self.worktree.mkdir()
        self.supervisor.create(self.spec, str(self.worktree), "b" * 40, "harness/safe-demo")

    def tearDown(self):
        self.tmp.cleanup()

    def advance_to_test(self):
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)

    def drain(self):
        for _ in range(30):
            state = self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
            if state == State.PASS:
                return state
            for child in list(self.supervisor.process._children.values()):
                child.wait()
            self.supervisor.collect_jobs(self.spec.mission_id)
        self.fail("did not finish")

    def test_background_verify_continues_same_mission_without_duplicate(self):
        self.advance_to_test()
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        rows = self.journal.db.execute("SELECT job_id FROM jobs").fetchall()
        self.assertEqual(len(rows), 1)
        # Natural language says incomplete; supervisor polls its registered job instead of ending/restarting it.
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
        self.assertEqual(self.drain(), State.PASS)
        self.assertEqual(self.codex.thread, "thread-1")

    def test_cli_style_supervision_waits_for_owned_gate_and_finishes(self):
        self.advance_to_test()
        self.assertEqual(self.supervisor.run_until_terminal(self.spec.mission_id, self.spec), State.PASS)
        self.assertFalse(self.journal.status(self.spec.mission_id).background_jobs)

    def test_pending_review_stays_pending_without_repair_turn(self):
        self.adapter.reviews = ["PENDING"]
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.REVIEW)
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.REVIEW)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["pending_gate"], "review:codex")
        self.assertEqual(self.codex.turns, [])

    def test_codex_turn_claim_serializes_controllers_and_unknown_outcome_fails_closed(self):
        self.supervisor.step(self.spec.mission_id, self.spec)  # CREATED -> PREPARING
        self.supervisor.step(self.spec.mission_id, self.spec)  # PREPARING -> IMPLEMENT
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(self.journal.claim_codex_turn(self.spec.mission_id, owner_pid, owner_start), "CLAIMED")
        second = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "second-turn-logs"),
                            self.codex, self.adapter)
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.IMPLEMENT)
        self.assertEqual(self.codex.turns, [])
        self.journal.update(self.spec.mission_id, codex_turn_pid=99999999, codex_turn_start_ticks="gone")
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)

    def test_completed_codex_turn_is_consumed_after_restart_without_replay(self):
        """A crash after turn completion cannot launch a duplicate writable turn."""
        self.supervisor.step(self.spec.mission_id, self.spec)  # CREATED -> PREPARING
        self.supervisor.step(self.spec.mission_id, self.spec)  # PREPARING -> IMPLEMENT
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(
            self.journal.claim_codex_turn(self.spec.mission_id, owner_pid, owner_start),
            "CLAIMED",
        )
        self.journal.record_codex_thread(self.spec.mission_id, "thread-1", owner_pid, owner_start)
        self.journal.complete_codex_turn(self.spec.mission_id, "turn-1", owner_pid, owner_start)

        replacement = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "turn-restart-logs"),
            self.codex,
            self.adapter,
        )
        self.assertEqual(replacement.step(self.spec.mission_id, self.spec), State.TEST)
        self.assertEqual(self.codex.turns, [])
        self.assertEqual(self.journal.mission(self.spec.mission_id)["codex_turn_state"], "CONSUMED")

    def test_completed_production_turn_rechecks_dirty_checkpoint_after_restart(self):
        """Durable completion cannot bypass a post-reconcile worktree mutation."""
        repo = Path(self.tmp.name) / "completed-dirty-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("clean\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

        class DirtyAfterReconcileAdapter(FootballPredictionAdapter):
            def exact_head(self, worktree):
                Path(worktree, "uncheckpointed.txt").write_text("late model edit\n")
                return head

        spec = replace(self.spec, adapter="footballprediction")
        journal = Journal(Path(self.tmp.name) / "completed-dirty.sqlite")
        journal.create(spec, worktree=str(repo), base_sha="b" * 40,
                       branch="harness/completed-dirty")
        journal.update(spec.mission_id, current_head=head, current_state=State.IMPLEMENT)
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(journal.claim_codex_turn(spec.mission_id, owner_pid, owner_start), "CLAIMED")
        journal.record_codex_thread(spec.mission_id, "thread-1", owner_pid, owner_start)
        journal.complete_codex_turn(spec.mission_id, "turn-1", owner_pid, owner_start)

        replacement = Supervisor(
            journal,
            ProcessSupervisor(journal, Path(self.tmp.name) / "completed-dirty-logs"),
            self.codex,
            DirtyAfterReconcileAdapter(),
        )
        self.assertEqual(replacement.step(spec.mission_id, spec), State.BLOCKED_EXTERNAL)
        self.assertEqual(self.codex.turns, [])
        self.assertEqual(journal.mission(spec.mission_id)["codex_turn_state"], "COMPLETED")

    def test_completed_production_turn_blocks_when_checkpoint_inspection_fails(self):
        """An unavailable Git checkpoint inspection is not treated as clean."""
        spec = replace(self.spec, adapter="footballprediction")
        self.journal.db.execute(
            "UPDATE missions SET spec_json=?,current_head=?,current_state=? WHERE mission_id=?",
            (json.dumps(spec.__dict__), "a" * 40, State.IMPLEMENT, spec.mission_id),
        )
        self.journal.db.commit()
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(
            self.journal.claim_codex_turn(spec.mission_id, owner_pid, owner_start),
            "CLAIMED",
        )
        self.journal.record_codex_thread(spec.mission_id, "thread-1", owner_pid, owner_start)
        self.journal.complete_codex_turn(spec.mission_id, "turn-1", owner_pid, owner_start)
        replacement = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "checkpoint-error-logs"),
            self.codex,
            FootballPredictionAdapter(),
        )
        with patch("harness.supervisor.subprocess.run", side_effect=OSError("git unavailable")):
            self.assertFalse(replacement._agent_turn(spec.mission_id, "resume", ()))
        self.assertEqual(self.journal.status(spec.mission_id).state, State.BLOCKED_EXTERNAL)
        self.assertEqual(self.codex.turns, [])

    def test_noop_journal_paths_leave_sqlite_transaction_clean(self):
        """Lease-loss and zero-row invalidation paths must not poison the connection."""
        self.journal.invalidate_reviews(self.spec.mission_id, "a" * 40)
        with self.assertRaisesRegex(RuntimeError, "thread persistence"):
            self.journal.record_codex_thread(self.spec.mission_id, "thread", 99999999, "gone")
        with self.assertRaisesRegex(RuntimeError, "completion persistence"):
            self.journal.complete_codex_turn(self.spec.mission_id, "turn", 99999999, "gone")
        self.journal.fail_codex_turn(self.spec.mission_id, "stale owner", 99999999, "gone")
        self.journal.transition(self.spec.mission_id, State.PREPARING, "transaction paths recovered")

    def test_atomic_mission_creation_persists_isolation_metadata(self):
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["worktree"], str(self.worktree))
        self.assertEqual(row["base_sha"], "b" * 40)
        self.assertEqual(row["branch"], "harness/safe-demo")

    def test_codex_policy_boundary_disables_network_and_limits_writes(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = ("live_provider_request", "quota_consumption")
        adapter._policy_cwd = "/tmp/mission-worktree"
        params = adapter._policy_params("/ignored")
        self.assertEqual(params["approvalPolicy"], "on-request")
        self.assertFalse(params["sandboxPolicy"]["networkAccess"])
        self.assertEqual(params["sandboxPolicy"]["writableRoots"], ["/tmp/mission-worktree"])

    def test_codex_policy_baseline_is_not_optional(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._configured_forbidden_actions = adapter._effective_policy(())
        adapter._forbidden_actions = adapter._effective_policy(())
        adapter._policy_cwd = "/tmp/mission-worktree"
        params = adapter._policy_params("/ignored")
        self.assertEqual(params["approvalPolicy"], "on-request")
        self.assertFalse(params["sandboxPolicy"]["networkAccess"])

    def test_production_build_injects_immutable_mission_codex_policy(self):
        denied = ("live_provider_request", "quota_consumption")
        fake = FakeCodex()
        with patch("harness.cli.AppServerCodex", return_value=fake) as constructor:
            supervisor = build(Path(self.tmp.name), "footballprediction",
                               forbidden_actions=denied)
        constructor.assert_called_once_with(forbidden_actions=denied)
        self.assertIs(supervisor.codex, fake)

        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._configured_forbidden_actions = denied
        adapter._forbidden_actions = denied
        adapter._policy_cwd = None
        with self.assertRaisesRegex(RuntimeError, "configured mission deny-list"):
            adapter.set_policy(("merge",), "/tmp/mission-worktree")

    def test_football_adapter_rejects_dirty_worktree_before_head_evidence(self):
        repo = Path(self.tmp.name) / "git-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("clean\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
        adapter = FootballPredictionAdapter()
        self.assertEqual(len(adapter.exact_head(str(repo))), 40)
        (repo / "tracked.txt").write_text("dirty\n")
        with self.assertRaisesRegex(RuntimeError, "clean committed worktree"):
            adapter.exact_head(str(repo))

    def test_docker_namespace_is_unique_and_non_destructive(self):
        self.assertNotEqual(compose_namespace("same mission"), compose_namespace("same/mission"))
        self.assertTrue(docker_env("m1")["COMPOSE_PROJECT_NAME"].startswith("cmh-"))
        self.assertTrue(compose_namespace("任务-1").isascii())

    def test_mission_id_cannot_escape_worktree_root(self):
        with self.assertRaisesRegex(ValueError, "safe worktree identifier"):
            WorktreeManager().ensure("/safe/repo", "../../escape", Path(self.tmp.name) / "trees")

    def test_worktree_porcelain_parser_ignores_space_less_metadata(self):
        self.assertEqual(WorktreeManager._record_values([
            "worktree /tmp/mission path", "HEAD " + "a" * 40, "detached", "bare"
        ]), {"worktree": "/tmp/mission path", "HEAD": "a" * 40})

    def test_existing_mission_path_rejects_detached_and_foreign_worktrees(self):
        repo = Path(self.tmp.name) / "repo"
        (repo / ".git").mkdir(parents=True)
        root = Path(self.tmp.name) / "trees"
        expected = str((root / "safe-demo").resolve())

        def fake_run(*argv, cwd=None):
            if argv[-1] == "origin/main":
                return "b" * 40
            if argv[-2:] == ("list", "--porcelain"):
                return fake_run.listing
            raise AssertionError(argv)

        manager = WorktreeManager()
        for metadata in ("detached", "branch refs/heads/harness/another-mission"):
            with self.subTest(metadata=metadata):
                fake_run.listing = f"worktree {expected}\nHEAD {'a' * 40}\n{metadata}"
                with patch("harness.isolation.run", side_effect=fake_run):
                    with self.assertRaisesRegex(RuntimeError, "detached or belongs to another branch"):
                        manager.ensure(str(repo), "safe-demo", root)

        fake_run.listing = f"worktree {expected}\nHEAD {'a' * 40}\nbranch refs/heads/harness/safe-demo"
        with patch("harness.isolation.run", side_effect=fake_run):
            tree = manager.ensure(str(repo), "safe-demo", root)
        self.assertEqual(tree.branch, "harness/safe-demo")

    def test_head_change_invalidates_both_reviews(self):
        self.advance_to_test()
        self.drain()  # first run establishes receipts for A
        self.assertEqual(self.journal.valid_reviews(self.spec.mission_id, "a" * 40), {"codex", "deepseek"})
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.valid_reviews(self.spec.mission_id, "b" * 40), set())
        invalid = self.journal.db.execute("SELECT count(*) FROM receipts WHERE invalidated=1").fetchone()[0]
        self.assertEqual(invalid, 2)

    def test_head_change_after_gates_rewinds_to_fresh_exact_head_validation(self):
        self.advance_to_test()
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        for child in self.supervisor.process._children.values(): child.wait()
        self.supervisor.collect_jobs(self.spec.mission_id)
        self.assertTrue(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        self.supervisor.step(self.spec.mission_id, self.spec)  # TEST -> REVIEW
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        self.assertFalse(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "b" * 40))

    def test_head_change_invalidates_owner_approval_and_requires_new_grant(self):
        owner_spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(owner_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.WAITING_APPROVAL,
                            approval_state="PENDING", pending_gate="owner-merge")
        self.journal.approve(self.spec.mission_id, "merge", "head A only")
        self.assertTrue(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "b" * 40))

    def test_existing_mission_spec_is_durable_authority_for_cli_and_supervisor(self):
        persisted, exists = reconcile_supplied_spec(self.journal, self.spec)
        self.assertTrue(exists)
        self.assertEqual(persisted, self.spec)
        for changed in (
            replace(self.spec, adapter="footballprediction"),
            replace(self.spec, required_gates=("other-gate",)),
            replace(self.spec, merge_policy="owner_approval"),
            replace(self.spec, forbidden_actions=("merge",)),
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "persisted mission contract"):
                    reconcile_supplied_spec(self.journal, changed)
                with self.assertRaisesRegex(RuntimeError, "persisted mission contract"):
                    self.supervisor.step(self.spec.mission_id, changed)

    def test_corrupt_persisted_spec_fails_closed(self):
        self.journal.db.execute("UPDATE missions SET spec_json='{}' WHERE mission_id=?", (self.spec.mission_id,))
        self.journal.db.commit()
        with self.assertRaisesRegex(RuntimeError, "persisted mission spec is invalid"):
            self.journal.spec(self.spec.mission_id)

    def test_approval_is_bound_to_known_action_policy_head_and_pending_state(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.WAITING_APPROVAL,
                            approval_state="PENDING", pending_gate="owner-merge")
        with self.assertRaisesRegex(ValueError, "unknown or non-sensitive"):
            self.journal.approve(self.spec.mission_id, "typo")
        with self.assertRaisesRegex(ValueError, "does not require approval"):
            self.journal.approve(self.spec.mission_id, "merge")

        owner_spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(owner_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        with self.assertRaisesRegex(RuntimeError, "observed canonical HEAD differs"):
            self.journal.approve(self.spec.mission_id, "merge", observed_head="b" * 40)
        self.journal.approve(self.spec.mission_id, "merge", observed_head="a" * 40)
        self.assertTrue(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))

        denied_spec = replace(owner_spec, forbidden_actions=("merge",))
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(denied_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        with self.assertRaisesRegex(PermissionError, "mission forbids action"):
            self.journal.approve(self.spec.mission_id, "merge", observed_head="a" * 40)

    def test_approval_cannot_be_pregranted_or_bound_to_missing_head(self):
        owner_spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(owner_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        with self.assertRaisesRegex(RuntimeError, "canonical HEAD reconciliation"):
            self.journal.approve(self.spec.mission_id, "merge")
        self.journal.update(self.spec.mission_id, current_head="a" * 40)
        with self.assertRaisesRegex(RuntimeError, "not waiting for approval"):
            self.journal.approve(self.spec.mission_id, "merge")

    def test_pass_is_reopened_when_canonical_head_changes(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.PASS, terminal_state=State.PASS, merge_claim_head="a" * 40)
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        self.assertFalse(self.journal.status(self.spec.mission_id).terminal)
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["merge_claim_head"])

    def test_head_reconciliation_clears_stale_terminal_marker_from_nonpass_state(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.REVIEW, terminal_state=State.PASS)
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["current_state"], State.TEST)
        self.assertIsNone(row["terminal_state"])

    def test_pending_review_marker_is_cleared_when_reviewer_resolves(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.REVIEW,
                            pending_gate="review:codex", ci_state="PENDING")
        self.adapter.reviews = ["PASS"]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.REVIEW)
        row = self.journal.mission(self.spec.mission_id)
        self.assertIsNone(row["pending_gate"])
        self.assertIsNone(row["ci_state"])

    def test_pending_ci_marker_is_cleared_when_ci_resolves(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.CI,
                            pending_gate="github-ci", ci_state="PENDING")
        self.adapter.ci_results = ["PASS"]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.MERGE)
        row = self.journal.mission(self.spec.mission_id)
        self.assertIsNone(row["pending_gate"])
        self.assertIsNone(row["ci_state"])

    def test_simulation_approval_uses_synthetic_head_not_git(self):
        spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=?,current_head=?,current_state=?,approval_state=?,pending_gate=? WHERE mission_id=?",
                                (json.dumps(spec.__dict__), "a" * 40, State.WAITING_APPROVAL,
                                 "PENDING", "owner-merge", spec.mission_id))
        self.journal.db.commit()
        with patch("harness.cli.git_run", side_effect=AssertionError("simulation must not query Git")):
            self.assertEqual(approval_head(self.journal, spec, self.journal.mission(spec.mission_id)), "a" * 40)

    def test_production_codex_dirty_checkpoint_fails_closed_before_test(self):
        repo = Path(self.tmp.name) / "dirty-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("clean\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)

        class DirtyCodex(FakeCodex):
            def turn(self, thread_id, prompt, cwd):
                Path(cwd, "uncheckpointed.txt").write_text("model edit\n")
                return super().turn(thread_id, prompt, cwd)

        spec = replace(self.spec, adapter="footballprediction")
        journal = Journal(Path(self.tmp.name) / "dirty.sqlite")
        supervisor = Supervisor(journal, ProcessSupervisor(journal, Path(self.tmp.name) / "dirty-logs"),
                                DirtyCodex(), FootballPredictionAdapter())
        supervisor.create(spec, str(repo), "b" * 40, "harness/dirty")
        supervisor.step(spec.mission_id, spec)
        supervisor.step(spec.mission_id, spec)
        self.assertEqual(supervisor.step(spec.mission_id, spec), State.BLOCKED_EXTERNAL)
        self.assertNotEqual(journal.status(spec.mission_id).state, State.TEST)

    def test_review_p1_and_ci_fail_are_repaired_not_blocked(self):
        self.adapter.reviews = ["FAIL", "PASS", "PASS"]
        self.adapter.ci_results = ["FAIL", "PASS"]
        self.advance_to_test()
        self.assertEqual(self.drain(), State.PASS)
        events = [row[0] for row in self.journal.db.execute("SELECT kind FROM events").fetchall()]
        self.assertGreaterEqual(events.count("codex_turn"), 3)

    def test_restart_resume_reconciles_not_restart_zero(self):
        self.advance_to_test()
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        old_process = self.supervisor.process
        child = next(iter(old_process._children.values()))
        child.wait()  # deterministic controlled interruption point: command ended before supervisor restart
        replacement = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "logs"), self.codex, self.adapter)
        # The replacement observes the persisted RUNNING row and the reaped PID,
        # marks that unjournaled outcome LOST, and resumes the same mission at TEST.
        replacement.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["current_state"], State.TEST)
        self.assertEqual(row["current_head"], "a" * 40)
        self.assertEqual(row["codex_thread_id"], "thread-1")
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM events WHERE kind='mission_created'").fetchone()[0], 1)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE state='LOST'").fetchone()[0], 1)
        replacement.collect_jobs(self.spec.mission_id)
        self.supervisor = replacement
        self.assertEqual(self.drain(), State.PASS)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='verify-pr'").fetchone()[0], 2)

    def test_agent_prose_is_not_terminal_and_invalid_transition_fails_closed(self):
        self.advance_to_test()
        self.assertFalse(self.journal.status(self.spec.mission_id).terminal)
        with self.assertRaises(InvalidTransition):
            self.journal.transition(self.spec.mission_id, State.PASS, "agent prose")

    def test_transition_is_exact_state_and_head_compare_and_swap(self):
        self.journal.update(self.spec.mission_id, current_state=State.REVIEW,
                            current_head="a" * 40)
        other = Journal(Path(self.tmp.name) / "harness.sqlite")
        other.reconcile_head(self.spec.mission_id, "b" * 40)
        with self.assertRaisesRegex(InvalidTransition, "expected state|expected HEAD"):
            self.journal.transition(
                self.spec.mission_id, State.CI, "stale review decision",
                expected_state=State.REVIEW, expected_head="a" * 40,
            )
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["current_state"], row["current_head"]),
                         (State.TEST, "b" * 40))

    def test_run_until_wait_stably_returns_blocked_external(self):
        self.adapter.reviews = ["BLOCKED_EXTERNAL"]
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.REVIEW)
        self.assertEqual(
            self.supervisor.run_until_wait(self.spec.mission_id, self.spec),
            State.BLOCKED_EXTERNAL,
        )
        # Re-entry is terminal and must not consume another reviewer result or
        # fall through the progress loop.
        review_index = self.adapter.review_index
        self.assertEqual(
            self.supervisor.run_until_wait(self.spec.mission_id, self.spec),
            State.BLOCKED_EXTERNAL,
        )
        self.assertEqual(self.adapter.review_index, review_index)

    def test_policy_block_is_a_stable_terminal_wait_state(self):
        spec = replace(self.spec, forbidden_actions=("source_edit",))
        self.journal.db.execute("UPDATE missions SET spec_json=?,current_state=? WHERE mission_id=?",
                                (json.dumps(spec.__dict__), State.IMPLEMENT, spec.mission_id))
        self.journal.db.commit()
        self.assertEqual(self.supervisor.run_until_wait(spec.mission_id, spec), State.BLOCKED_POLICY)
        self.assertEqual(self.supervisor.run_until_terminal(spec.mission_id, spec), State.BLOCKED_POLICY)

    def test_app_server_turn_requires_completed_notification(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.proc = type("Process", (), {"stdout": StringIO(
            '{"method":"turn/started","params":{}}\n'
            '{"method":"turn/completed","params":{"threadId":"t","turn":'
            '{"id":"x","status":"completed","items":[{"type":"agentMessage","text":"done"}]}}}\n'
        )})()
        turn = adapter._turn_completed("t", "x")
        self.assertEqual(turn["status"], "completed")

    def test_app_server_eof_fails_closed(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.seq = 0
        adapter.proc = type("Process", (), {"stdin": StringIO(), "stdout": StringIO()})()
        with self.assertRaisesRegex(RuntimeError, "exited before"):
            adapter._request("ping", {})

    def test_app_server_rejects_unsolicited_server_request(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.seq = 0
        adapter.proc = type("Process", (), {
            "stdin": StringIO(),
            "stdout": StringIO(
                '{"id":99,"method":"item/commandExecution/requestApproval","params":{}}\n'
                '{"id":1,"result":{"ok":true}}\n'
            ),
        })()
        self.assertEqual(adapter._request("ping", {}), {"ok": True})
        self.assertIn("request denied by mission harness policy", adapter.proc.stdin.getvalue())

    def test_gate_pass_is_bound_to_exact_head(self):
        self.journal.complete_gate(self.spec.mission_id, "verify-pr", "a" * 40)
        self.assertTrue(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        self.assertFalse(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "b" * 40))

    def test_process_reservation_prevents_duplicate_launch(self):
        process = self.supervisor.process
        first = process.start(self.spec.mission_id, "one-gate", ["/bin/sh", "-c", "exit 0"], str(self.worktree), {}, "a" * 40)
        second = process.start(self.spec.mission_id, "one-gate", ["/bin/sh", "-c", "exit 0"], str(self.worktree), {}, "a" * 40)
        self.assertEqual(first, second)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='one-gate'").fetchone()[0], 1)
        next(iter(process._children.values())).wait()
        process.poll(self.spec.mission_id)

    def test_restart_poll_records_zero_exit_from_reaped_child(self):
        job_id = "reaped-zero"
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,pid,pgid,start_ticks,state,stdout_path,stderr_path,started_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, self.spec.mission_id, "verify-pr", "[]", "a" * 40, 123, 123, "old-ticks", "RUNNING", "", "", "now"),
        )
        self.journal.db.commit()
        replacement = ProcessSupervisor(self.journal, Path(self.tmp.name) / "reaped-logs")
        with patch("harness.process.proc_start_ticks", return_value=None), patch(
                "harness.process.os.waitpid", return_value=(123, 0)):
            result = replacement.poll(self.spec.mission_id)
        self.assertEqual([(item.state, item.exit_code) for item in result], [("EXITED", 0)])
        self.assertEqual(tuple(self.journal.db.execute(
            "SELECT state,exit_code FROM jobs WHERE job_id=?", (job_id,)).fetchone()), ("EXITED", 0))

    def test_proc_identity_permission_error_fails_closed(self):
        with patch("harness.process.Path.read_text", side_effect=PermissionError):
            self.assertIsNone(proc_start_ticks(123))
        with patch("harness.journal.Path.read_text", side_effect=PermissionError):
            self.assertIsNone(Journal._proc_start_ticks(123))

    def test_stale_gate_failure_cannot_trigger_repair_for_new_head(self):
        self.adapter.heads = ["b" * 40]
        self.journal.update(self.spec.mission_id, current_head="b" * 40, current_state=State.TEST,
                            pending_gate="verify-pr")
        stale = JobResult("old-job", "EXITED", 17, "a" * 40)
        with patch.object(self.supervisor.process, "poll", return_value=[stale]):
            self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["pending_gate"], "verify-pr")
        event = self.journal.db.execute(
            "SELECT payload_json FROM events WHERE kind='gate_failure_stale' ORDER BY seq DESC LIMIT 1").fetchone()
        self.assertIsNotNone(event)
        payload = json.loads(event[0])
        self.assertEqual(payload["launch_head"], "a" * 40)
        self.assertEqual(payload["current_head"], "b" * 40)
        self.assertEqual(payload["exit_code"], 17)

    def test_stale_starting_lease_is_recoverable_before_a_replacement_launch(self):
        """A crash before PID publication is marked lost before a replacement launch."""
        job_id = "reserved-only"
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,stdout_path,stderr_path,started_at,launcher_pid,launcher_start_ticks,lease_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, self.spec.mission_id, "verify-pr", "[]", "a" * 40, "STARTING", "", "", "now", 99999999, "never", "lease"),
        )
        self.journal.db.commit()
        result = self.supervisor.process.poll(self.spec.mission_id)
        self.assertEqual([(item.job_id, item.state) for item in result], [(job_id, "LOST")])
        replacement = self.supervisor.process.start(self.spec.mission_id, "verify-pr", ["/bin/sh", "-c", "exit 0"], str(self.worktree), {}, "a" * 40)
        self.assertNotEqual(replacement, job_id)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='verify-pr'").fetchone()[0], 2)
        self.supervisor.process._children[replacement].wait()
        self.supervisor.process.poll(self.spec.mission_id)

    def test_restart_gate_crash_points_fail_closed_and_recover(self):
        self.advance_to_test()
        # completed-but-not-journaled after a controller restart becomes LOST, not PASS
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        child = next(iter(self.supervisor.process._children.values()))
        child.wait()
        restarted = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "restarted-logs"), self.codex, self.adapter)
        restarted.reconcile(self.spec.mission_id)
        self.assertFalse(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        # Retry from canonical TEST truth, then simulate a crash after gate journal but before state transition.
        restarted.run_until_wait(self.spec.mission_id, self.spec)
        for child in list(restarted.process._children.values()):
            child.wait()
        restarted.collect_jobs(self.spec.mission_id)
        self.assertTrue(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        replacement = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "again-logs"), self.codex, self.adapter)
        self.assertEqual(replacement.run_until_wait(self.spec.mission_id, self.spec), State.PASS)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='verify-pr'").fetchone()[0], 2)

    def test_owner_approval_is_persisted_and_resume_consumes_only_explicit_grant(self):
        spec = MissionSpec("approval-demo", "/safe/repo", "approval fixture", adapter="simulation", merge_policy="owner_approval")
        worktree = Path(self.tmp.name) / "approval-worktree"; worktree.mkdir()
        supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "approval-logs"), self.codex, SimulatedAdapter())
        supervisor.create(spec, str(worktree), "b" * 40, "harness/approval-demo")
        for _ in range(20):
            state = supervisor.run_until_wait(spec.mission_id, spec)
            if state == State.WAITING_APPROVAL:
                break
            for child in list(supervisor.process._children.values()):
                child.wait()
            supervisor.collect_jobs(spec.mission_id)
        self.assertEqual(state, State.WAITING_APPROVAL)
        self.assertFalse(self.journal.approved(spec.mission_id, "merge", "a" * 40))
        resumed = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "approval-restart"), self.codex, supervisor.adapter)
        self.assertEqual(resumed.step(spec.mission_id, spec), State.WAITING_APPROVAL)
        self.journal.approve(spec.mission_id, "merge", "explicit owner command")
        for _ in range(10):
            state = resumed.run_until_wait(spec.mission_id, spec)
            if state == State.PASS:
                break
        self.assertEqual(state, State.PASS)

    def test_simulation_cli_build_selects_simulated_contract_adapter(self):
        supervisor = build(Path(self.tmp.name), "simulation", FakeCodex())
        self.assertIsInstance(supervisor.adapter, SimulatedAdapter)

    def test_invalid_adapter_names_fail_closed_and_simulation_does_not_start_app_server(self):
        path = Path(self.tmp.name) / "bad.json"
        path.write_text(json.dumps({"schema_version": 1, "mission_id": "x", "repository": "/r", "objective": "x", "adapter": "sim"}))
        with self.assertRaises(ValueError):
            load_spec(path)
        path.write_text(json.dumps({"schema_version": True, "mission_id": "x", "repository": "/r", "objective": "x"}))
        with self.assertRaises(ValueError):
            load_spec(path)
        supervisor = build(Path(self.tmp.name), "simulation")
        self.assertIsInstance(supervisor.codex, FixtureCodex)
        self.assertNotIsInstance(supervisor.codex, AppServerCodex)

    def test_forbidden_merge_is_denied_before_claim(self):
        spec = MissionSpec("deny-merge", "/safe/repo", "fixture", adapter="simulation", merge_policy="auto", forbidden_actions=("merge",))
        worktree = Path(self.tmp.name) / "deny-worktree"; worktree.mkdir()
        supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "deny-logs"), self.codex, self.adapter)
        supervisor.create(spec, str(worktree), "b" * 40, "harness/deny-merge")
        self.journal.update(spec.mission_id, current_head="a" * 40, current_state=State.MERGE)
        self.assertEqual(supervisor.step(spec.mission_id, spec), State.BLOCKED_POLICY)
        self.assertIsNone(self.journal.mission(spec.mission_id)["merge_claim_head"])

    def test_first_merge_claim_executes_external_merge(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(self.adapter.merged_heads, {"a" * 40})
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_claim_head"], "a" * 40)

    def test_merge_failure_is_external_not_policy_denial(self):
        class FailingMergeAdapter(SimulatedAdapter):
            def merge(self, worktree, head):
                return GateResult("FAIL", "remote merge service rejected request")

        adapter = FailingMergeAdapter()
        supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "merge-fail-logs"),
                                self.codex, adapter)
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)

    def test_merge_exception_after_claim_blocks_without_retrying_unknown_outcome(self):
        class RaisingMergeAdapter(SimulatedAdapter):
            def merge(self, worktree, head):
                self.merged_heads.add(head)
                raise RuntimeError("transport disconnected after request")

        adapter = RaisingMergeAdapter()
        supervisor = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "merge-exception-logs"),
            self.codex,
            adapter,
        )
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=head,
            current_state=State.MERGE,
            merge_claim_head=None,
            merge_claim_pid=None,
            merge_claim_start_ticks=None,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)
        self.assertEqual(adapter.merged_heads, {head})
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_claim_head"], head)

    def test_unknown_merge_decision_fails_closed_before_claim(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        with patch("harness.supervisor.decide", return_value="UNRECOGNIZED"):
            self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_POLICY)
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["merge_claim_head"])

    def test_head_drift_during_deliver_rewinds_and_merge_claim_recovers(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.DELIVER)
        self.adapter.heads = ["b" * 40]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.TEST)
        for child in list(self.supervisor.process._children.values()):
            child.wait()
        self.supervisor.collect_jobs(self.spec.mission_id)
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head="a" * 40, merge_claim_pid=99999999,
                            merge_claim_start_ticks="dead-owner")
        self.adapter.heads = ["a" * 40]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(self.adapter.merged_heads, {"a" * 40})

    def test_head_drift_during_post_merge_reopens_before_delivery(self):
        class DriftingPostMergeAdapter(SimulatedAdapter):
            def post_merge(self, gate, head):
                self.heads = ["b" * 40]
                return GateResult("PASS", "post-merge completed before drift")

        adapter = DriftingPostMergeAdapter(heads=["a" * 40])
        supervisor = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "post-merge-drift-logs"),
            self.codex,
            adapter,
        )
        spec = replace(self.spec, post_merge_gates=("production-gate",))
        self.journal.update(
            self.spec.mission_id,
            spec_json=json.dumps(spec.__dict__),
            current_head="a" * 40,
            current_state=State.POST_MERGE,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, spec), State.TEST)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["current_head"], "b" * 40)

    def test_head_drift_at_final_delivery_check_reopens_before_pass(self):
        class SequenceHeadAdapter(SimulatedAdapter):
            def __init__(self):
                super().__init__(heads=["a" * 40])
                self.observations = iter(["a" * 40, "b" * 40])

            def exact_head(self, worktree):
                return next(self.observations, "b" * 40)

        adapter = SequenceHeadAdapter()
        supervisor = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "deliver-drift-logs"),
            self.codex,
            adapter,
        )
        self.journal.update(
            self.spec.mission_id,
            current_head="a" * 40,
            current_state=State.DELIVER,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.TEST)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["current_head"], "b" * 40)

    def test_live_merge_claim_cannot_be_stolen_by_second_controller(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        owner_pid, owner_start_ticks = self.supervisor._merge_owner()
        self.assertTrue(self.journal.claim_merge(self.spec.mission_id, "a" * 40, owner_pid, owner_start_ticks))
        second = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "second-logs"),
                            self.codex, self.adapter)
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_claim_head"], "a" * 40)
        self.assertEqual(self.adapter.merged_heads, set())

    def test_head_drift_preserves_live_merge_claim_then_revalidates_after_safe_reclaim(self):
        old_head, new_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=old_head,
            current_state=State.MERGE,
            merge_claim_head=None,
            merge_claim_pid=None,
            merge_claim_start_ticks=None,
        )
        owner_pid, owner_start_ticks = self.supervisor._merge_owner()
        self.assertTrue(
            self.journal.claim_merge(
                self.spec.mission_id, old_head, owner_pid, owner_start_ticks,
            )
        )

        # A concurrent source update must not erase the live claim: its owner
        # may still be between the durable claim and the external merge call.
        self.adapter.heads = [new_head]
        self.supervisor.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["current_state"], row["current_head"]), (State.MERGE, new_head))
        self.assertEqual(row["merge_claim_head"], old_head)

        second = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "drifted-claim-logs"),
            self.codex,
            self.adapter,
        )
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(self.adapter.merged_heads, set())

        # Once canonical status says NOT_STARTED and the recorded owner is
        # definitely gone, reclaim atomically rewinds to TEST for the new HEAD;
        # it still cannot merge the new HEAD in the same supervisor turn.
        self.journal.update(
            self.spec.mission_id,
            merge_claim_pid=99999999,
            merge_claim_start_ticks="dead-owner",
        )
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.TEST)
        row = self.journal.mission(self.spec.mission_id)
        self.assertIsNone(row["merge_claim_head"])
        self.assertEqual(row["current_head"], new_head)
        self.assertEqual(self.adapter.merged_heads, set())

    def test_completed_stale_head_merge_blocks_instead_of_merging_new_head(self):
        old_head, new_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=old_head,
            current_state=State.MERGE,
            merge_claim_head=old_head,
            merge_claim_pid=99999999,
            merge_claim_start_ticks="dead-owner",
        )
        self.adapter.merged_heads.add(old_head)
        self.adapter.heads = [new_head]

        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(
            self.supervisor.step(self.spec.mission_id, self.spec),
            State.BLOCKED_EXTERNAL,
        )
        self.assertEqual(self.adapter.merged_heads, {old_head})
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["merge_claim_head"], old_head)
        self.assertEqual(row["current_head"], new_head)

    def test_dead_merge_claim_is_reclaimed_only_after_canonical_not_started(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head="a" * 40, merge_claim_pid=99999999,
                            merge_claim_start_ticks="dead-owner")
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(self.adapter.merged_heads, {"a" * 40})
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_claim_head"], "a" * 40)

    def test_unknown_merge_claim_identity_fails_closed(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head="a" * 40, merge_claim_pid=None, merge_claim_start_ticks=None)
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)
        self.assertEqual(self.adapter.merged_heads, set())

    def test_football_adapter_review_fails_closed_instead_of_crashing(self):
        result = FootballPredictionAdapter().review("codex", "a" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

from __future__ import annotations

import tempfile
import unittest
from io import StringIO
from pathlib import Path

from harness.adapters import FootballPredictionAdapter, SimulatedAdapter
from harness.cli import build
from harness.codex import AppServerCodex, Turn
from harness.domain import InvalidTransition, MissionSpec, State
from harness.isolation import compose_namespace, docker_env
from harness.journal import Journal
from harness.process import ProcessSupervisor
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

    def test_docker_namespace_is_unique_and_non_destructive(self):
        self.assertNotEqual(compose_namespace("same mission"), compose_namespace("same/mission"))
        self.assertTrue(docker_env("m1")["COMPOSE_PROJECT_NAME"].startswith("cmh-"))

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
        self.journal.update(self.spec.mission_id, current_head="a" * 40)
        self.journal.approve(self.spec.mission_id, "merge", "head A only")
        self.assertTrue(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "b" * 40))

    def test_pass_is_reopened_when_canonical_head_changes(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.PASS, terminal_state=State.PASS, merge_claim_head="a" * 40)
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        self.assertFalse(self.journal.status(self.spec.mission_id).terminal)
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["merge_claim_head"])

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
        self.supervisor.reconcile(self.spec.mission_id)
        replacement = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "logs"), self.codex, self.adapter)
        replacement.collect_jobs(self.spec.mission_id)
        self.supervisor = replacement
        self.assertEqual(self.drain(), State.PASS)
        self.assertIsNotNone(old_process)

    def test_agent_prose_is_not_terminal_and_invalid_transition_fails_closed(self):
        self.advance_to_test()
        self.assertFalse(self.journal.status(self.spec.mission_id).terminal)
        with self.assertRaises(InvalidTransition):
            self.journal.transition(self.spec.mission_id, State.PASS, "agent prose")

    def test_app_server_turn_requires_completed_notification(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.proc = type("Process", (), {"stdout": StringIO(
            '{"method":"turn/started","params":{}}\n'
            '{"method":"turn/completed","params":{"threadId":"t","turn":'
            '{"id":"x","status":"completed","items":[{"type":"agentMessage","text":"done"}]}}}\n'
        )})()
        turn = adapter._turn_completed("t", "x")
        self.assertEqual(turn["status"], "completed")

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

    def test_stale_starting_lease_is_recoverable_without_a_second_launch(self):
        """A crash before PID publication is safe: bootstrap had no release payload."""
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

    def test_football_adapter_review_fails_closed_instead_of_crashing(self):
        result = FootballPredictionAdapter().review("codex", "a" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

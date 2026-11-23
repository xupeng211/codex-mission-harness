"""Offline validation of ordered implementation checkpoints through Factory.run."""
import json
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, IMPLEMENTATION_CHECKPOINT, READY, git
from harness.factory_fixture import AcceptanceRuntime, fixture_config


class DependentRuntime(AcceptanceRuntime):
    def __init__(self, *, first_usage=30, unknown=False, failing_check=False):
        super().__init__()
        self.first_usage = first_usage
        self.unknown = unknown
        self.failing_check = failing_check
        self.gate_calls = []

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        if role != "implement":
            result = super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
            if role == "plan":
                result["output"]["tasks"] = ["Add average", "Implement a consumer of average"]
                result["usage"] = {"input_tokens": 15, "output_tokens": 5}
                transcript.write_text(json.dumps(result["output"]))
            return result
        index = payload["task_index"]
        self.calls.append({"role": role, "task_index": index, "head": git(cwd, "rev-parse", "HEAD")})
        if index == 0:
            (cwd / "score.py").write_text((cwd / "score.py").read_text() +
                                          "\ndef average(values):\n    return sum(values) / len(values)\n")
            (cwd / "tests").mkdir()
            (cwd / "tests/test_average.py").write_text(
                "import unittest\nfrom score import average\n"
                "class StageOne(unittest.TestCase):\n"
                "    def test_average(self): self.assertEqual(average([1, 2]), 1.5)\n")
        else:
            if "def average" not in git(cwd, "show", "HEAD:score.py"):
                raise AssertionError("dependent assignment requires a committed first stage")
            (cwd / "consumer.py").write_text("from score import average\n\ndef doubled(values):\n    return 2 * average(values)\n")
            (cwd / "tests/test_consumer.py").write_text(
                "import unittest\nfrom consumer import doubled\n"
                "class StageTwo(unittest.TestCase):\n"
                "    def test_doubled(self): self.assertEqual(doubled([1, 2]), 3)\n")
        transcript.write_text(f"offline implementation {index}\n")
        if index == 1 and self.unknown:
            return {"status": "UNKNOWN"}
        count = self.first_usage if index == 0 else 25
        return {"output": {"summary": f"Completed assignment {index}", "known_risks": []},
                "usage": {"input_tokens": count, "output_tokens": 0} if count is not None else None}

    def gate(self, command, cwd, target, transcript, timeout):
        self.gate_calls.append((command, target["head"]))
        if self.failing_check:
            transcript.write_text("targeted check failed\n")
            return {"status": "FAIL", "exit_code": 1}
        return super().gate(command, cwd, target, transcript, timeout)


class ImplementationCheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        source = self.root / "source"
        source.mkdir()
        (source / "score.py").write_text("def add(a, b):\n    return a + b\n")
        git(source, "init", "-q")
        git(source, "add", ".")
        git(source, "-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-qm", "base")
        self.base = git(source, "rev-parse", "HEAD")
        self.spec = {"version": 2, "mission_id": "dependent", "repository": str(source),
                     "base": self.base, "objective": "Implement average and its dependent consumer"}
        self.config = fixture_config()
        self.config["implementation_checkpoints"] = True
        self.config["budget"] = {"max_agent_runs": 5, "max_run_tokens": 50,
                                 "max_total_tokens": 250, "max_wall_seconds": 3600}
        self.factory = None
        self.addCleanup(self.close)

    def close(self):
        if self.factory is not None:
            self.factory.close()

    def open(self, **options):
        self.close()
        self.runtime = DependentRuntime(**options)
        self.factory = Factory(self.root / "state", self.config, self.runtime)
        return self.factory

    def run_mission(self):
        return self.factory.run(self.spec["mission_id"])

    def snapshot(self):
        operations = self.factory.db.execute("SELECT * FROM operations ORDER BY rowid").fetchall()
        return {op["id"]: (tuple(op), Path(op["evidence"]).read_bytes(),
                           {raw["path"]: Path(raw["path"]).read_bytes()
                            for raw in json.loads(op["result"])["raw_evidence"]})
                for op in operations}

    def first_stage(self, **options):
        self.open(**options).submit(self.spec)
        report = self.run_mission()
        self.assertEqual(report["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT, report)
        self.assertEqual(report["TEST_RESULT"], "UNKNOWN")
        self.assertEqual(report["REVIEW_RESULT"], "UNKNOWN")
        self.assertEqual([call["role"] for call in self.runtime.calls], ["plan", "implement"])
        receipt, = report["IMPLEMENTATION_CHECKPOINTS"]
        self.cwd = Path(report["CANDIDATE"])
        self.first_head = receipt["target"]["head"]
        self.assertNotEqual(self.first_head, self.base)
        self.assertEqual(git(self.cwd, "status", "--porcelain"), "")
        self.assertEqual(self.runtime.gate_calls, [(self.config["checks"][0], self.first_head)])
        self.assertEqual(len(receipt["checks"]), 1)
        return self.snapshot()

    def test_reopen_dispatches_only_dependent_work_and_runs_final_gates(self):
        initial = self.first_stage()
        self.open()
        self.assertEqual(self.snapshot(), initial)
        final = self.run_mission()
        self.assertEqual(final["DELIVERY_STATUS"], READY, final)
        self.assertEqual(self.runtime.calls[0], {"role": "implement", "task_index": 1, "head": self.first_head})
        self.assertEqual([call["role"] for call in self.runtime.calls], ["implement", "review", "review"])
        self.assertEqual(self.runtime.gate_calls, [(self.config[kind][0], final["TARGET_HEAD"])
                                                   for kind in ("checks", "ci")])
        self.assertEqual(git(self.cwd, "rev-parse", "HEAD^"), self.first_head)
        self.assertEqual(set(final["EXACT_TARGET"]["files"]),
                         {"score.py", "consumer.py", "tests/test_average.py", "tests/test_consumer.py"})
        self.assertEqual(final["BUDGET_USED"]["agent_runs"], 5)
        self.assertEqual(final["BUDGET_USED"]["observed_tokens"], 75)
        after = self.snapshot()
        self.assertEqual({key: after[key] for key in initial}, initial)
        self.open()
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], READY)
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), after)

    def test_unknown_dependent_result_is_retained_and_never_replayed(self):
        initial = self.first_stage()
        self.open(unknown=True)
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN", stopped)
        self.assertEqual(self.runtime.calls, [{"role": "implement", "task_index": 1, "head": self.first_head}])
        self.assertEqual(stopped["BUDGET_USED"]["unknown_token_reservation"], 50)
        self.assertEqual(stopped["BUDGET_USED"]["agent_runs"], 3)
        self.assertEqual(git(self.cwd, "rev-parse", "HEAD"), self.first_head)
        self.assertTrue((self.cwd / "consumer.py").is_file())
        after = self.snapshot()
        self.assertEqual({key: after[key] for key in initial}, initial)
        self.open()
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), after)

    def test_dirty_worktree_stops_before_reservation(self):
        initial = self.first_stage()
        (self.cwd / "outside.txt").write_text("external edit")
        self.open()
        self.assertEqual(self.factory.report(self.spec["mission_id"])["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)
        self.assertEqual((self.cwd / "outside.txt").read_text(), "external edit")

    def test_externally_advanced_clean_head_stops_before_reservation(self):
        initial = self.first_stage()
        git(self.cwd, "-c", "user.name=External", "-c", "user.email=external@localhost",
            "commit", "--allow-empty", "-qm", "external commit")
        foreign_head = git(self.cwd, "rev-parse", "HEAD")
        self.open()
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)
        self.assertEqual(git(self.cwd, "rev-parse", "HEAD"), foreign_head)

    def test_insufficient_authorization_keeps_original_tokens_reserved(self):
        self.config["budget"]["max_total_tokens"] = 100
        initial = self.first_stage(first_usage=None)
        self.open()
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_BUDGET", stopped)
        self.assertEqual(stopped["BUDGET_USED"]["committed_tokens"], 70)
        self.assertEqual(stopped["BUDGET_USED"]["unknown_token_reservation"], 50)
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "BLOCKED_BUDGET")
        self.assertEqual(self.snapshot(), initial)

    def test_original_wall_clock_still_applies_after_reopen(self):
        initial = self.first_stage()
        self.open()
        with patch("harness.factory.time.time", return_value=time.time() + 3601):
            stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_BUDGET", stopped)
        self.assertIn("wall-clock", stopped["BLOCKERS_REMAINING"][0])
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)

    def test_missing_checkpoint_log_prevents_resume(self):
        initial = self.first_stage()
        check = next(op for op in self.factory.db.execute("SELECT * FROM operations") if op["stage"] == "checks")
        raw = Path(json.loads(check["result"])["raw_evidence"][0]["path"])
        raw.write_text("changed check log")
        self.open()
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN")
        self.assertIn("raw execution evidence", stopped["BLOCKERS_REMAINING"][0])
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(raw.read_text(), "changed check log")
        self.assertEqual([tuple(row) for row in self.factory.db.execute("SELECT * FROM operations ORDER BY rowid")],
                         [record[0] for record in initial.values()])

    def test_failed_targeted_check_does_not_accept_stage_one(self):
        self.open(failing_check=True).submit(self.spec)
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_VALIDATION", stopped)
        self.assertNotIn("IMPLEMENTATION_CHECKPOINTS", stopped)
        self.assertEqual([call["role"] for call in self.runtime.calls], ["plan", "implement"])
        initial = self.snapshot()
        self.open()
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "BLOCKED_VALIDATION")
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)

    def test_interruption_before_acceptance_cannot_advance(self):
        self.open().submit(self.spec)
        with patch.object(self.factory, "gates", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.run_mission()
        initial = self.snapshot()
        self.open()
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN", stopped)
        self.assertIn("lacks a durable checkpoint", stopped["BLOCKERS_REMAINING"][0])
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)

    def test_project_pr_gates_receive_only_the_cumulative_candidate(self):
        from test_factory_controller_gates import CONTAINER, DELIVERY, LIMITS, LiveProtocolDouble
        from test_factory_project import ProjectContractTests

        project = ProjectContractTests()
        project.setUp()
        self.addCleanup(project.doCleanups)
        project.scope["authorized_paths"] += ["consumer.py", "tests/test_average.py", "tests/test_consumer.py"]
        spec = {**project.spec, "approved_mission_scope": project.approval(),
                "pr_body_template": "OFFLINE PR body {{candidate_head}} {{review_timestamp}}"}
        config = {**project.config, "simulation": False, "implementation_checkpoints": True,
                  "project_container": CONTAINER, "project_delivery": DELIVERY,
                  "project_review_limits": LIMITS, "checks": [["make", "verify-targeted"]],
                  "ci": [["make", "verify-strict"]], "budget": self.config["budget"]}
        state = self.root / "project-state"
        with patch("harness.factory_preflight.inspect_prepaid", return_value={"status": "PASS", "findings": []}):
            runtime = LiveProtocolDouble()
            runtime.agent = DependentRuntime().agent
            with closing(Factory(state, config, runtime)) as factory:
                checkpoint = factory.run(factory.submit(spec))
                self.assertEqual(checkpoint["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT, checkpoint)
                self.assertIsNone(runtime.remote)
                self.assertEqual(runtime.calls, [])
            runtime = LiveProtocolDouble()
            builder = DependentRuntime()
            runtime.agent = builder.agent
            with closing(Factory(state, config, runtime)) as factory:
                final = factory.run(spec["mission_id"])
                self.assertEqual(final["DELIVERY_STATUS"], READY, final)
                self.assertEqual([call["task_index"] for call in builder.calls], [1])
                self.assertEqual(runtime.remote.writes, ["push", "create"])
                self.assertEqual(runtime.remote.raw["head"]["sha"], final["TARGET_HEAD"])
                self.assertFalse(final["MERGE_PERFORMED"])
                final_steps = factory.db.execute(
                    "SELECT stage,input FROM operations WHERE stage IN ('review','project_publish','project_ci','project_verify')"
                ).fetchall()
                self.assertTrue({"review", "project_publish", "project_ci", "project_verify"}
                                <= {op["stage"] for op in final_steps})
                for op in final_steps:
                    target = json.loads(op["input"])["target"]
                    self.assertEqual((target["base"], target["head"]), (spec["base"], final["TARGET_HEAD"]))

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
    def __init__(self, *, first_usage=30, unknown=False, failing_check=False, first_change="complete", tasks=None):
        super().__init__()
        self.first_usage = first_usage
        self.unknown = unknown
        self.failing_check = failing_check
        self.first_change = first_change
        self.tasks = tasks or ["Add average", "Implement a consumer of average"]
        self.gate_calls = []
        self.gate_workspaces = []

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        if role != "implement":
            result = super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
            if role == "plan":
                result["output"]["tasks"] = self.tasks
                result["usage"] = {"input_tokens": 15, "output_tokens": 5}
                transcript.write_text(json.dumps(result["output"]))
            return result
        index = payload["task_index"]
        self.calls.append({"role": role, "task_index": index, "head": git(cwd, "rev-parse", "HEAD")})
        if index == 0 and self.first_change in {"complete", "ignored"}:
            (cwd / "score.py").write_text((cwd / "score.py").read_text() +
                                          "\ndef average(values):\n    return sum(values) / len(values)\n")
            (cwd / "tests").mkdir()
            (cwd / "tests/test_average.py").write_text(
                "import unittest\nfrom score import average\n"
                "class StageOne(unittest.TestCase):\n"
                "    def test_average(self): self.assertEqual(average([1, 2]), 1.5)\n")
            if self.first_change == "ignored":
                (cwd / "local_seed.txt").write_text("not an approved input\n")
        elif index == 0 and self.first_change == "unrelated":
            (cwd / "notes.txt").write_text("does not implement average\n")
        elif index == 1:
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
        self.gate_workspaces.append(cwd)
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
        (source / ".gitignore").write_text("local_seed.txt\n")
        git(source, "init", "-q")
        git(source, "add", ".")
        git(source, "-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-qm", "base")
        self.base = git(source, "rev-parse", "HEAD")
        self.spec = {"version": 2, "mission_id": "dependent", "repository": str(source),
                     "base": self.base, "objective": "Implement average and its dependent consumer"}
        self.config = fixture_config()
        self.config["implementation_checkpoints"] = True
        self.config["implementation_checkpoint_outputs"] = [["score.py", "tests/test_average.py"]]
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
        self.assertEqual(receipt["outputs"], self.config["implementation_checkpoint_outputs"][0])
        self.assertNotIn(self.cwd, self.runtime.gate_workspaces)
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
        self.assertNotIn(self.cwd, self.runtime.gate_workspaces)
        self.assertEqual(git(self.cwd, "rev-parse", "HEAD^"), self.first_head)
        self.assertEqual(set(final["EXACT_TARGET"]["files"]),
                         {"score.py", "consumer.py", "tests/test_average.py", "tests/test_consumer.py"})
        clean = self.root / "clean-checkout"
        git(self.cwd, "clone", "--no-local", "--no-hardlinks", "--", str(self.cwd), str(clean))
        self.assertEqual(git(clean, "rev-parse", "HEAD"), final["TARGET_HEAD"])
        self.assertEqual(git(clean, "rev-parse", "HEAD^{tree}"), final["EXACT_TARGET"]["tree"])
        self.assertEqual(AcceptanceRuntime().gate(self.config["checks"][0], clean, final["EXACT_TARGET"],
                                                 self.root / "clean-checks.raw", 30)["status"], "PASS")
        self.assertEqual(final["BUDGET_USED"]["agent_runs"], 5)
        self.assertEqual(final["BUDGET_USED"]["observed_tokens"], 75)
        after = self.snapshot()
        self.assertEqual({key: after[key] for key in initial}, initial)
        self.open()
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], READY)
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), after)
        (self.cwd / "local_seed.txt").write_text("unapproved input after delivery\n")
        self.assertEqual(self.factory.report(self.spec["mission_id"])["DELIVERY_STATUS"], "UNKNOWN")

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

    def test_ignored_input_stops_before_reservation_on_reopen(self):
        initial = self.first_stage()
        input_file = self.cwd / "local_seed.txt"
        input_file.write_text("not an approved input\n")
        self.assertEqual(git(self.cwd, "status", "--porcelain"), "")
        self.open()
        self.assertEqual(self.factory.report(self.spec["mission_id"])["DELIVERY_STATUS"], "UNKNOWN")
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN")
        self.assertIn("outside committed Git source", stopped["BLOCKERS_REMAINING"][0])
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)
        self.assertEqual(input_file.read_text(), "not an approved input\n")

    def test_ignored_input_from_builder_cannot_reach_checks_or_acceptance(self):
        self.open(first_change="ignored").submit(self.spec)
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN", stopped)
        self.assertNotIn("IMPLEMENTATION_CHECKPOINTS", stopped)
        self.assertEqual(self.runtime.gate_calls, [])
        self.assertTrue((Path(stopped["CANDIDATE"]) / "local_seed.txt").is_file())

    def test_tracked_bytes_hidden_from_git_status_stop_before_reservation(self):
        initial = self.first_stage()
        git(self.cwd, "update-index", "--assume-unchanged", "--", "score.py")
        path = self.cwd / "score.py"
        path.write_text(path.read_text() + "\n# modified after acceptance\n")
        self.assertEqual(git(self.cwd, "status", "--porcelain"), "")
        self.open()
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN", stopped)
        self.assertIn("differs from committed HEAD", stopped["BLOCKERS_REMAINING"][0])
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)

    def test_empty_or_unrelated_work_cannot_satisfy_required_outputs(self):
        for change in ("none", "unrelated"):
            with self.subTest(change=change):
                self.spec["mission_id"] = change
                self.open(first_change=change).submit(self.spec)
                stopped = self.run_mission()
                self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_VALIDATION", stopped)
                self.assertIn("required changed output: score.py", stopped["BLOCKERS_REMAINING"][0])
                self.assertNotIn("IMPLEMENTATION_CHECKPOINTS", stopped)
                self.assertEqual([call["role"] for call in self.runtime.calls], ["plan", "implement"])
                self.assertEqual(self.runtime.gate_calls, [])
                initial = self.snapshot()
                self.open()
                self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "BLOCKED_VALIDATION")
                self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
                self.assertEqual(self.snapshot(), initial)

    def test_call_count_only_budget_stops_before_first_builder(self):
        self.config["budget"] = {"max_agent_runs": 3}
        self.open().submit(self.spec)
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_BUDGET", stopped)
        self.assertEqual([call["role"] for call in self.runtime.calls], ["plan"])
        self.assertEqual(stopped["BUDGET_USED"]["agent_runs"], 1)
        self.assertEqual(self.runtime.gate_calls, [])
        self.assertNotIn("IMPLEMENTATION_CHECKPOINTS", stopped)
        initial = self.snapshot()
        self.open()
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "BLOCKED_BUDGET")
        self.assertEqual(self.runtime.calls + self.runtime.gate_calls, [])
        self.assertEqual(self.snapshot(), initial)

    def test_staged_plan_without_output_authority_stops_before_first_builder(self):
        del self.config["implementation_checkpoint_outputs"]
        self.open().submit(self.spec)
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_VALIDATION", stopped)
        self.assertIn("authorized checkpoint outputs", stopped["BLOCKERS_REMAINING"][0])
        self.assertEqual([call["role"] for call in self.runtime.calls], ["plan"])

    def test_plan_cannot_collapse_approved_assignments(self):
        self.open(tasks=["Implement everything"]).submit(self.spec)
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_VALIDATION", stopped)
        self.assertEqual([call["role"] for call in self.runtime.calls], ["plan"])
        requirements = self.runtime.calls[0]["payload"]["checkpoint_requirements"]
        self.assertEqual(requirements["task_count"], 2)
        self.assertEqual(requirements["nonfinal_outputs"], self.config["implementation_checkpoint_outputs"])
        self.assertEqual(stopped["BUDGET_USED"]["agent_runs"], 1)
        actual = self.snapshot()
        self.open()
        self.assertEqual(self.run_mission()["DELIVERY_STATUS"], "BLOCKED_VALIDATION")
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.snapshot(), actual)

    def test_first_plan_requires_the_controller_prepared_head_and_tree(self):
        mission = self.open().submit(self.spec)
        _, cwd = self.factory.prepare(mission)
        prepared = self.factory.checkpoint_start(mission)
        self.assertEqual(prepared, {"head": self.base, "tree": git(cwd, "rev-parse", "HEAD^{tree}")})
        (cwd / "external.txt").write_text("external commit before planning\n")
        git(cwd, "add", ".")
        git(cwd, "-c", "user.name=External", "-c", "user.email=external@localhost",
            "commit", "-qm", "external advance")
        external = git(cwd, "rev-parse", "HEAD")
        self.assertEqual(git(cwd, "status", "--porcelain"), "")
        self.open()
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN", stopped)
        self.assertIn("Controller-prepared start", stopped["BLOCKERS_REMAINING"][0])
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.snapshot(), {})
        self.assertEqual(git(cwd, "rev-parse", "HEAD"), external)
        self.assertEqual(self.factory.checkpoint_start(mission), prepared)

    def test_review_rechecks_ignored_and_hidden_tracked_drift_before_reservation(self):
        for variant in ("ignored", "tracked"):
            with self.subTest(variant=variant):
                self.spec["mission_id"] = variant
                initial = self.first_stage()
                self.open()
                original = self.factory.review_context

                def changed_context(spec, cwd, target, lane):
                    checkout = original(spec, cwd, target, lane)
                    if variant == "ignored":
                        (checkout / "local_seed.txt").write_text("outside review input\n")
                    else:
                        git(checkout, "update-index", "--assume-unchanged", "--", "score.py")
                        with (checkout / "score.py").open("a") as stream:
                            stream.write("\n# outside review input\n")
                    self.assertEqual(git(checkout, "status", "--porcelain"), "")
                    return checkout

                with patch.object(self.factory, "review_context", side_effect=changed_context):
                    stopped = self.run_mission()
                self.assertEqual(stopped["DELIVERY_STATUS"], "UNKNOWN", stopped)
                reason = "outside committed Git source" if variant == "ignored" else "differs from committed HEAD"
                self.assertIn(reason, stopped["BLOCKERS_REMAINING"][0])
                self.assertEqual([call["role"] for call in self.runtime.calls], ["implement"])
                self.assertEqual(self.factory.db.execute(
                    "SELECT COUNT(*) FROM operations WHERE mission=? AND stage='review'",
                    (self.spec["mission_id"],)).fetchone()[0], 0)
                after = self.snapshot()
                self.assertEqual({key: after[key] for key in initial}, initial)

    def test_checkpoint_output_outside_scope_stops_before_first_builder(self):
        self.spec["scope"] = ["score.py"]
        self.open().submit(self.spec)
        stopped = self.run_mission()
        self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_SCOPE", stopped)
        self.assertEqual([call["role"] for call in self.runtime.calls], ["plan"])

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
        for mode in ("dual", "single_openai"):
            with self.subTest(mode=mode):
                self.check_project_pr_gates(mode)

    def check_project_pr_gates(self, mode):
        from test_factory_controller_gates import CONTAINER, DELIVERY, LIMITS, LiveProtocolDouble
        from test_factory_project import ProjectContractTests

        project = ProjectContractTests()
        project.setUp()
        self.addCleanup(project.doCleanups)
        project.scope["authorized_paths"] += ["consumer.py", "tests/test_average.py", "tests/test_consumer.py"]
        spec = {**project.spec, "approved_mission_scope": project.approval(),
                "pr_body_template": "OFFLINE PR body {{candidate_head}} {{review_timestamp}}"}
        config = {**project.config, "simulation": False, "implementation_checkpoints": True,
                  "implementation_checkpoint_outputs": self.config["implementation_checkpoint_outputs"],
                  "project_container": CONTAINER, "project_delivery": DELIVERY,
                  "project_review_limits": LIMITS, "checks": [["make", "verify-targeted"]],
                  "ci": [["make", "verify-strict"]], "budget": self.config["budget"]}
        config["review_mode"] = mode
        if mode == "single_openai":
            config["profiles"].pop("second_reviewer")
        state = self.root / f"project-state-{mode}"
        with patch("harness.factory_preflight.inspect_prepaid", return_value={"status": "PASS", "findings": []}):
            runtime = LiveProtocolDouble()
            runtime.agent = DependentRuntime().agent
            with closing(Factory(state, config, runtime)) as factory:
                mission = factory.submit(spec)
                checkpoint = factory.run(mission)
                self.assertEqual(checkpoint["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT, checkpoint)
                start = factory.checkpoint_start(mission)
                self.assertNotEqual(start["head"], spec["base"])
                plan = json.loads(factory.db.execute("SELECT input FROM operations WHERE stage='plan'").fetchone()[0])
                self.assertEqual(plan["workspace"]["dispatch_head"], start["head"])
                self.assertEqual(plan["workspace"]["dispatch_tree"], start["tree"])
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
                expected_lanes = ["reviewer"] if mode == "single_openai" else ["reviewer", "second_reviewer"]
                review_operations = factory.db.execute("SELECT lane FROM operations WHERE stage='review' ORDER BY rowid")
                self.assertEqual([row["lane"] for row in review_operations], expected_lanes)
                final_steps = factory.db.execute(
                    "SELECT stage,input FROM operations WHERE stage IN ('review','project_publish','project_ci','project_verify')"
                ).fetchall()
                self.assertTrue({"review", "project_publish", "project_ci", "project_verify"}
                                <= {op["stage"] for op in final_steps})
                for op in final_steps:
                    target = json.loads(op["input"])["target"]
                    self.assertEqual((target["base"], target["head"]), (spec["base"], final["TARGET_HEAD"]))

    def test_project_scope_is_checked_before_reserving_the_builder(self):
        from test_factory_project import ProjectContractTests, ProjectRuntime

        project = ProjectContractTests()
        project.setUp()
        self.addCleanup(project.doCleanups)
        builder = DependentRuntime()
        runtime = ProjectRuntime()
        runtime.agent = builder.agent
        config = {**project.config, "implementation_checkpoints": True,
                  "implementation_checkpoint_outputs": self.config["implementation_checkpoint_outputs"]}
        # The mission's default generic scope permits the file. The approved
        # project scope omits it.
        with closing(Factory(self.root / "restricted-project", config, runtime)) as factory:
            mission = factory.submit(project.spec)
            stopped = factory.run(mission)
            self.assertEqual(stopped["DELIVERY_STATUS"], "BLOCKED_SCOPE", stopped)
            self.assertIn("project rejected checkpoint outputs", stopped["BLOCKERS_REMAINING"][0])
            self.assertEqual([call["role"] for call in builder.calls], ["plan"])
            self.assertEqual([row[0] for row in factory.db.execute("SELECT stage FROM operations")], ["plan"])
            cwd = Path(stopped["CANDIDATE"])
            self.assertEqual(git(cwd, "rev-parse", "HEAD"), factory.checkpoint_start(mission)["head"])
            self.assertFalse((cwd / "tests/test_average.py").exists())

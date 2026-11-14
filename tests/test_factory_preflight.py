"""Static admission and planning guard regressions; no Provider inference."""
from __future__ import annotations

import copy
import hashlib
import json
import shlex
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness.factory import Factory, FactoryBlocked, READY, git, validate_config
from harness.factory_budget import planning_limits
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_preflight import CONFIG_BYTES, MAKE_BYTES, committed_text, docker_gate, inspect_prepaid, make_docker_dependency, text_capacity, workflow_push
from harness.factory_runtime import FactoryAppServer, LocalRuntime, RuntimeFailure


class PrepaidPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "score.py").write_text("def add(a, b):\n    return a + b\n")
        (self.repo / "historical-UNKNOWN.json").write_text('{"status":"UNKNOWN","usage":null}\n')
        self.commit()
        self.config = fixture_config()
        self.spec = {"version": 2, "mission_id": "feature", "repository": str(self.repo), "objective": "Add average"}

    def commit(self):
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Test", "-c", "user.email=t@localhost", "commit", "-qm", "fixture")

    def factory(self, config=None, runtime=None):
        f = Factory(self.root / "state", config or self.config, runtime or AcceptanceRuntime())
        self.addCleanup(f.close)
        f.submit(self.spec)
        return f

    def assert_zero_dispatch(self, factory):
        before = {str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.repo.rglob("*") if p.is_file()}
        with patch.object(factory.runtime, "agent", side_effect=AssertionError("paid dispatch forbidden")) as agent, \
             patch.object(factory.runtime, "gate", side_effect=AssertionError("diagnostic test forbidden")) as gate:
            report = factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_PREFLIGHT", report)
        self.assertEqual(factory.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
        agent.assert_not_called()
        gate.assert_not_called()
        after = {str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.repo.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(report["PREPAID_PREFLIGHT"]["delivery_ready_asserted"])
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 0)
        return report

    def test_context_capacity_blocks_before_any_paid_reservation_or_project_command(self):
        self.config["max_context_bytes"] = 10
        report = self.assert_zero_dispatch(self.factory())
        self.assertIn("independent_context", report["BLOCKERS_REMAINING"][0])

    def single_config(self):
        config = copy.deepcopy(self.config)
        config["review_mode"] = "single_openai"
        config["profiles"].pop("second_reviewer")
        config["max_context_bytes"] = 10
        return config

    def test_single_skips_disabled_full_source_lane_but_reviews_and_reworks(self):
        config = self.single_config()
        self.assertTrue(config["independent_review_required"])
        f = self.factory(config)
        # Same baseline and limit as the dual blocker above. The disabled
        # lane's capacity scanner must not even run, not merely hide its result.
        with patch("harness.factory_preflight.text_capacity", side_effect=AssertionError("disabled lane scanned")):
            report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertEqual(report["SECOND_REVIEW_STATUS"], "NOT_ENABLED")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 5)
        self.assertEqual([call["role"] for call in f.runtime.calls],
                         ["plan", "implement", "review", "rework", "review"])
        self.assertEqual(f.db.execute("SELECT COUNT(*) FROM operations WHERE lane='second_reviewer'").fetchone()[0], 0)

    def test_single_keeps_full_diff_limit_after_skipping_disabled_lane_capacity(self):
        config = self.single_config()
        config["max_review_bytes"] = 10
        f = self.factory(config)
        report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_SCOPE", report)
        self.assertIn("nothing was truncated", report["BLOCKERS_REMAINING"][0])
        self.assertEqual([call["role"] for call in f.runtime.calls], ["plan", "implement"])

    def test_single_keeps_budget_limit_after_skipping_disabled_lane_capacity(self):
        config = self.single_config()
        config["budget"]["max_agent_runs"] = 3
        f = self.factory(config)
        report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET", report)
        self.assertLessEqual(report["BUDGET_USED"]["agent_runs"], 3)
        self.assertNotIn("second_reviewer", [row[0] for row in f.db.execute("SELECT lane FROM operations")])

    def test_capacity_counts_utf8_regular_blobs_and_skips_binary_and_symlinks(self):
        (self.repo / "utf8.txt").write_text("中" * 10)
        (self.repo / "binary.bin").write_bytes(b"\0" * 1024)
        (self.repo / "invalid.bin").write_bytes(b"\xff" * 1024)
        (self.repo / "link").symlink_to("utf8.txt")
        self.commit()
        result = text_capacity(self.repo, git(self.repo, "rev-parse", "HEAD"), 4096)
        expected = sum((self.repo / name).stat().st_size for name in ("score.py", "historical-UNKNOWN.json", "utf8.txt"))
        self.assertEqual(result["text_bytes_lower_bound"], expected)
        self.assertTrue(result["scan_complete"])

    def test_incomplete_capacity_scan_is_unverified_and_never_a_fitting_claim(self):
        f = self.factory()
        with patch("harness.factory_preflight.SCAN_BYTES", 1):
            report = inspect_prepaid(json.loads(f.row("feature")["spec"]), f.config)
        finding = next(x for x in report["findings"] if x["check"] == "independent_context")
        self.assertEqual(finding["level"], "UNVERIFIED")
        self.assertFalse(finding["scan_complete"])
        self.assertFalse(report["delivery_ready_asserted"])

    def test_small_project_still_delivers_and_preflight_is_not_a_paid_operation(self):
        f = self.factory()
        report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 7)
        self.assertEqual(report["PREPAID_PREFLIGHT"]["status"], "NO_KNOWN_HARD_BLOCKER")
        kinds = [r[0] for r in f.db.execute("SELECT kind FROM events ORDER BY sequence")]
        self.assertLess(kinds.index("prepaid_preflight"), kinds.index("reserved"))
        self.assertEqual(kinds.count("prepaid_preflight"), 1)
        count = f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        self.assertEqual(f.run("feature")["DELIVERY_STATUS"], READY)
        self.assertEqual(f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], count)

    def test_main_only_hosted_ci_is_reported_before_paid_dispatch(self):
        workflow = self.repo / ".github/workflows/ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("on:\n  push:\n    branches: [main]\n  pull_request:\n")
        self.commit()
        self.config["hosted_ci"] = {"repository": "fixture/project", "workflows": ["ci.yml"]}
        report = self.assert_zero_dispatch(self.factory())
        self.assertIn("excludes Factory", report["BLOCKERS_REMAINING"][0])

    def test_missing_authorized_workflow_blocks_before_paid_dispatch(self):
        self.config["hosted_ci"] = {"repository": "fixture/project", "workflows": ["missing.yml"]}
        self.assert_zero_dispatch(self.factory())

    def test_reachable_make_docker_gate_blocks_without_executing_make(self):
        (self.repo / "Makefile").write_text("COMPOSE_DEV=docker compose -f docker-compose.dev.yml\nRUNNER=$(COMPOSE_DEV) exec -T dev python3 check.py\nverify:\n\t@$(MAKE) verify-strict\nverify-strict:\n\t@$(RUNNER) strict\n")
        self.commit()
        self.config["checks"] = [["make", "verify"]]
        report = self.assert_zero_dispatch(self.factory())
        self.assertIn("Docker-dependent", report["BLOCKERS_REMAINING"][0])

    def test_unrelated_docker_make_target_does_not_block_small_project(self):
        text = "verify:\n\tpython3 -m unittest\ndeploy:\n\tdocker compose up\n"
        self.assertFalse(make_docker_dependency(text, ["make", "verify"]))
        self.assertTrue(make_docker_dependency(text, ["make", "deploy"]))

    def test_oneshell_and_error_or_shell_overrides_remain_unverified(self):
        for prefix in (".ONESHELL:\n", ".IGNORE: verify\n", "SHELL=/bin/bash\n",
                       ".SHELLFLAGS=-n -c\n", "MAKEFLAGS += -n\n"):
            with self.subTest(prefix=prefix):
                body = prefix + "verify:\n\tif false; then\n\tdocker run image\n\tfi\n"
                (self.repo / "Makefile").write_text(body)
                self.commit()
                self.config["checks"] = [["make", "verify"]]
                spec = {**self.spec, "base": git(self.repo, "rev-parse", "HEAD")}
                result = inspect_prepaid(spec, validate_config(self.config))
                self.assertEqual(result["status"], "NO_KNOWN_HARD_BLOCKER")
                self.assertTrue(any(x["check"] == "checks[0]" and x["level"] == "UNVERIFIED" for x in result["findings"]))
                self.assertFalse(result["delivery_ready_asserted"])

    def test_default_goal_honors_literal_goal_without_changing_explicit_goal(self):
        body = ".DEFAULT_GOAL := verify\ndeploy:\n\tdocker run image\nverify:\n\tpython3 -m unittest\n"
        self.assertFalse(make_docker_dependency(body, ["make"]))
        self.assertFalse(make_docker_dependency(body, ["make", "verify"]))
        self.assertTrue(make_docker_dependency(body, ["make", "deploy"]))
        self.assertTrue(make_docker_dependency(body.replace(":= verify", ":= deploy"), ["make"]))
        with self.assertRaises(ValueError):
            make_docker_dependency(body.replace(":= verify", "= $(GOAL)"), ["make"])

    def test_football_style_comments_and_unrelated_shell_else_do_not_hide_docker(self):
        body = (".DEFAULT_GOAL := help\nMAKEFLAGS += --no-print-directory\n"
                "COMPOSE_DEV=docker compose -f docker-compose.dev.yml\n"
                "VALIDATION_PROFILE_RUNNER=$(COMPOSE_DEV) exec -T dev python3 check.py\n"
                "help: ## Usage: make help FORMAT=<name>\n\t@echo help\n"
                "other:\n\tif true; then echo ok; \\\n\telse echo other; fi\n"
                "verify:\n\t@$(MAKE) verify-strict\n"
                "verify-strict: ## Usage: make verify-strict MODE=<name>\n\t@$(VALIDATION_PROFILE_RUNNER) strict\n")
        self.assertTrue(make_docker_dependency(body, ["make", "verify"]))
        self.assertFalse(make_docker_dependency(body, ["make"]))

    def test_large_makefile_read_is_bounded_without_raising_workflow_or_paid_limits(self):
        (self.repo / "Makefile").write_text("#" + "x" * CONFIG_BYTES + "\n.DEFAULT_GOAL := verify\nverify:\n\tdocker compose exec dev pytest\n")
        self.commit()
        self.config["checks"] = [["make", "verify"]]
        self.assert_zero_dispatch(self.factory())
        (self.repo / "Makefile").write_text("#" + "x" * MAKE_BYTES + "\nverify:\n\tdocker run image\n")
        workflow = self.repo / ".github/workflows/oversized.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("#" + "x" * CONFIG_BYTES + "\non: push\n")
        self.commit()
        spec = {**self.spec, "base": git(self.repo, "rev-parse", "HEAD")}
        result = inspect_prepaid(spec, validate_config(self.config))
        self.assertEqual(result["status"], "NO_KNOWN_HARD_BLOCKER")
        self.assertTrue(any(x["check"] == "checks[0]" and x["level"] == "UNVERIFIED" for x in result["findings"]))
        with self.assertRaises(ValueError):
            committed_text(self.repo, spec["base"], ".github/workflows/oversized.yml")

    def test_optional_docker_and_queries_are_not_proven_environment_blockers(self):
        for recipe in ("docker --version", "docker compose config", "if false; then docker run image; fi",
                       "echo 'docker run image'", "-docker run image", "docker run image || true"):
            self.assertFalse(make_docker_dependency("verify:\n\t" + recipe + "\n", ["make", "verify"]))
        self.assertFalse(make_docker_dependency("RUN=echo\nRUN?=docker run\nverify:\n\t$(RUN) fixture\n", ["make", "verify"]))
        self.assertFalse(make_docker_dependency("RUN=echo\nRUN+=docker run\nverify:\n\t$(RUN) fixture\n", ["make", "verify"]))

    def test_dynamic_make_is_not_executed_or_misclassified_as_hard_blocker(self):
        marker = self.root / "must-not-exist"
        (self.repo / "Makefile").write_text(f"VALUE=$(shell touch {marker})\nverify:\n\tpython3 -m unittest\n")
        self.commit()
        self.config["checks"] = [["make", "verify"]]
        f = self.factory()
        result = inspect_prepaid(json.loads(f.row("feature")["spec"]), f.config)
        self.assertFalse(marker.exists())
        self.assertTrue(any(x["level"] == "UNVERIFIED" and x["check"] == "checks[0]" for x in result["findings"]))
        self.assertFalse(result["delivery_ready_asserted"])

    def test_make_dry_run_and_recursive_overrides_are_not_proven_docker_blockers(self):
        for command, text in ((["make", "-n", "verify"], "verify:\n\tdocker run image\n"),
                              (["make", "verify"], "verify:\n\t$(MAKE) -f Otherfile docker-check\ndocker-check:\n\tdocker run image\n"),
                              (["make", "verify"], "RUN=docker run\nverify: RUN=echo\nverify:\n\t$(RUN) fixture\n")):
            (self.repo / "Makefile").write_text(text)
            self.commit()
            self.config["checks"] = [command]
            spec = {**self.spec, "base": git(self.repo, "rev-parse", "HEAD")}
            result = inspect_prepaid(spec, validate_config(self.config))
            self.assertFalse(any(x["level"] == "HARD_BLOCKER" for x in result["findings"]))
            self.assertTrue(any(x["level"] == "UNVERIFIED" and x["check"] == "checks[0]" for x in result["findings"]))

    def test_literal_shell_docker_gate_is_blocked_without_a_docker_probe(self):
        self.config["checks"] = [["bash", "-lc", "docker compose exec dev pytest"]]
        self.assert_zero_dispatch(self.factory())

    def test_shell_noexec_and_complex_scripts_are_unverified_not_docker_blockers(self):
        marker = self.root / "must-not-execute-shell"
        for command in (["bash", "-n", "-c", "docker run image"],
                        ["bash", "-nc", "docker run image"],
                        ["sh", "-n", "-c", "docker run image"],
                        ["bash", "--noprofile", "-c", "docker run image"],
                        ["bash", "-c", "docker run image\ntrue"],
                        ["bash", "-c", "if false; then docker run image; fi"],
                        ["bash", "-c", f"docker run $(touch {marker})"]):
            with self.subTest(command=command):
                self.config["checks"] = [command]
                result = inspect_prepaid({**self.spec, "base": git(self.repo, "rev-parse", "HEAD")}, validate_config(self.config))
                self.assertEqual(result["status"], "NO_KNOWN_HARD_BLOCKER")
                self.assertTrue(any(x["check"] == "checks[0]" and x["level"] == "UNVERIFIED" for x in result["findings"]))
        self.assertFalse(marker.exists())

    def test_direct_docker_dependency_still_blocks_before_paid_dispatch(self):
        self.config["checks"] = [["docker", "compose", "-f", "compose.yml", "exec", "dev", "pytest"]]
        report = self.assert_zero_dispatch(self.factory())
        self.assertTrue(any(x["level"] == "HARD_BLOCKER" and "Docker-dependent" in x["detail"] for x in report["PREPAID_PREFLIGHT"]["findings"]))

    def test_container_program_help_blocks_before_any_paid_reservation(self):
        self.config["checks"] = [["bash", "-lc", "docker compose exec -T dev python3 -h"]]
        report = self.assert_zero_dispatch(self.factory())
        self.assertTrue(any(x["level"] == "HARD_BLOCKER" and "Docker-dependent" in x["detail"]
                            for x in report["PREPAID_PREFLIGHT"]["findings"]))

    def test_repository_docker_wrappers_and_help_are_not_daemon_proof(self):
        for command in (["./docker", "run", "fixture"], ["tools/docker", "run", "fixture"],
                        ["docker", "run", "--help"], ["docker", "run", "--rm", "--help"],
                        ["docker", "compose", "exec", "--help"]):
            with self.subTest(command=command):
                # Relative wrappers may be implemented by the task; only an
                # explicit ./ command bypasses the host executable lookup.
                self.config["checks"] = [command]
                result = inspect_prepaid({**self.spec, "base": git(self.repo, "rev-parse", "HEAD")}, validate_config(self.config))
                self.assertFalse(any(x["level"] == "HARD_BLOCKER" and "Docker-dependent" in x["detail"] for x in result["findings"]))

    def test_tag_only_workflow_blocks_before_reservation(self):
        workflow = self.repo / ".github/workflows/ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("on:\n  push:\n    tags: ['v*']\n")
        self.commit()
        self.config["hosted_ci"] = {"repository": "fixture/project", "workflows": ["ci.yml"]}
        report = self.assert_zero_dispatch(self.factory())
        self.assertIn("tag-only", report["BLOCKERS_REMAINING"][0])

    def test_absent_command_is_not_mistaken_for_a_ready_environment(self):
        self.config["checks"] = [["definitely-missing-prepaid-command"]]
        self.assert_zero_dispatch(self.factory())

    def test_live_missing_sandbox_is_detected_without_provider_or_auth_access(self):
        class OfflineLive(AcceptanceRuntime):
            simulation = False
        self.config["simulation"] = False
        f = self.factory(runtime=OfflineLive())
        import shutil
        real_which = shutil.which
        with patch("harness.factory_preflight.shutil.which", side_effect=lambda name, **kw: None if name == "bwrap" else real_which(name, **kw)):
            report = self.assert_zero_dispatch(f)
        self.assertIn("bwrap", report["BLOCKERS_REMAINING"][0])

    def test_preflight_does_not_change_authority_and_resume_cannot_raise_budget(self):
        original = copy.deepcopy(self.config)
        f = self.factory()
        authority = f.row("feature")["policy"]
        self.assertEqual(f.run("feature")["DELIVERY_STATUS"], READY)
        self.assertEqual(self.config, original)
        self.assertEqual(f.row("feature")["policy"], authority)
        f.config["budget"]["max_agent_runs"] += 1
        with self.assertRaisesRegex(ValueError, "immutable mission authority"):
            f.run("feature")

    def test_repaired_environment_resumes_under_frozen_authority_and_appends_preflight(self):
        import shutil
        real_which = shutil.which
        f = self.factory()
        frozen = (f.row("feature")["spec"], f.row("feature")["policy"])
        submitted = tuple(f.db.execute("SELECT * FROM events WHERE kind='submitted'").fetchone())
        with patch("harness.factory_preflight.shutil.which", side_effect=lambda name, **kw: None if name == "python3" else real_which(name, **kw)):
            self.assert_zero_dispatch(f)
        original = tuple(f.db.execute("SELECT * FROM events WHERE kind='prepaid_preflight'").fetchone())
        f.close()
        f = self.factory()
        self.assertEqual(f.run("feature")["DELIVERY_STATUS"], READY)
        events = f.db.execute("SELECT * FROM events WHERE kind='prepaid_preflight' ORDER BY sequence").fetchall()
        self.assertEqual(len(events), 2)
        self.assertEqual(tuple(events[0]), original)
        self.assertEqual(json.loads(events[1]["payload"])["status"], "NO_KNOWN_HARD_BLOCKER")
        first_reservation = f.db.execute("SELECT MIN(sequence) FROM events WHERE kind='reserved'").fetchone()[0]
        self.assertLess(events[1]["sequence"], first_reservation)
        self.assertEqual((f.row("feature")["spec"], f.row("feature")["policy"]), frozen)
        self.assertEqual(tuple(f.db.execute("SELECT * FROM events WHERE kind='submitted'").fetchone()), submitted)
        self.assertEqual(f.report("feature")["BUDGET_USED"]["agent_runs"], 7)

    def test_unrepaired_preflight_resume_remains_blocked_with_zero_usage(self):
        self.config["checks"] = [["definitely-missing-prepaid-command"]]
        f = self.factory()
        self.assert_zero_dispatch(f)
        original = tuple(f.db.execute("SELECT * FROM events WHERE kind='prepaid_preflight'").fetchone())
        self.assert_zero_dispatch(f)
        events = f.db.execute("SELECT * FROM events WHERE kind='prepaid_preflight' ORDER BY sequence").fetchall()
        self.assertEqual(len(events), 2)
        self.assertEqual(tuple(events[0]), original)

    def test_paid_completed_operation_prevents_preflight_resume_and_direct_bypass(self):
        f = self.factory()
        f.prepare("feature")
        f.operation("feature", "completed", "plan", "developer", {}, {}, True,
                    lambda t: {"output": {}, "usage": {"fixture_provider_calls": 0}})
        f.state("feature", "BLOCKED_PREFLIGHT", "offline paid-history guard fixture")
        operation = tuple(f.db.execute("SELECT * FROM operations").fetchone())
        budget = f.report("feature")["BUDGET_USED"]
        with patch("harness.factory_preflight.inspect_prepaid", side_effect=AssertionError("paid history must not be preflight-resumed")), \
             patch.object(f.runtime, "agent", side_effect=AssertionError("dispatch forbidden")):
            self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "BLOCKED_PREFLIGHT")
            with self.assertRaisesRegex(FactoryBlocked, "no paid operations"):
                f.operation("feature", "new", "plan", "developer", {}, {}, True, lambda t: {})
        self.assertEqual(tuple(f.db.execute("SELECT * FROM operations").fetchone()), operation)
        self.assertEqual(f.report("feature")["BUDGET_USED"], budget)

    def test_unknown_and_running_requests_cannot_resume_or_block_a_separate_new_mission(self):
        self.config["budget"].update(max_run_tokens=240000, max_total_tokens=8400000)
        f = self.factory()
        def unknown(t):
            raise RuntimeFailure("offline UNKNOWN", {"input_tokens": 1, "output_tokens": 0})
        def running(t):
            raise KeyboardInterrupt("offline controller death")
        for status, invoke, exception in (("UNKNOWN", unknown, FactoryBlocked), ("RUNNING", running, KeyboardInterrupt)):
            mission = status.lower()
            f.submit({**self.spec, "mission_id": mission})
            f.prepare(mission)
            with self.assertRaises(exception):
                f.operation(mission, "uncertain", "plan", "developer", {}, {}, True, invoke)
            f.state(mission, "BLOCKED_PREFLIGHT", "offline defensive resume fixture")
            before = tuple(f.db.execute("SELECT * FROM operations WHERE mission=?", (mission,)).fetchone())
            budget = f.report(mission)["BUDGET_USED"]
            with patch("harness.factory_preflight.inspect_prepaid", side_effect=AssertionError("no historical recheck")), \
                 patch.object(f.runtime, "agent", side_effect=AssertionError("no replay")):
                self.assertEqual(f.run(mission)["DELIVERY_STATUS"], "UNKNOWN")
                with self.assertRaisesRegex(FactoryBlocked, "unresolved operation"):
                    f.operation(mission, "new", "plan", "developer", {}, {}, True, lambda t: {})
            self.assertEqual(tuple(f.db.execute("SELECT * FROM operations WHERE mission=?", (mission,)).fetchone()), before)
            self.assertEqual(f.report(mission)["BUDGET_USED"], budget)
            self.assertEqual(budget["unknown_token_reservation"], 240000)
        self.assertEqual(f.run("feature")["DELIVERY_STATUS"], READY)

    def test_preflight_resume_does_not_reset_wall_clock_or_allow_authority_changes(self):
        import shutil
        real_which = shutil.which
        self.config["budget"]["max_wall_seconds"] = 3600
        f = self.factory()
        with patch("harness.factory_preflight.shutil.which", side_effect=lambda name, **kw: None if name == "python3" else real_which(name, **kw)):
            self.assert_zero_dispatch(f)
        frozen = tuple(f.db.execute("SELECT spec,policy FROM missions").fetchone())
        f.config["budget"]["max_agent_runs"] += 1
        with self.assertRaisesRegex(ValueError, "immutable mission authority"):
            f.run("feature")
        f.config["budget"]["max_agent_runs"] -= 1
        with self.assertRaisesRegex(ValueError, "immutable mission"):
            f.submit({**self.spec, "scope": ["score.py"]})
        with patch("harness.factory.time.time", return_value=time.time() + 3601), \
             patch.object(f.runtime, "agent", side_effect=AssertionError("expired authority must not dispatch")):
            self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "BLOCKED_BUDGET")
        self.assertEqual(tuple(f.db.execute("SELECT spec,policy FROM missions").fetchone()), frozen)
        self.assertEqual(f.report("feature")["BUDGET_USED"]["agent_runs"], 0)

    def test_crash_after_resumed_plan_recovers_complete_result_without_replay(self):
        import shutil
        real_which = shutil.which
        f = self.factory()
        with patch("harness.factory_preflight.shutil.which", side_effect=lambda name, **kw: None if name == "python3" else real_which(name, **kw)):
            self.assert_zero_dispatch(f)
        original_agent = f.agent
        def crash(*args):
            original_agent(*args)
            raise KeyboardInterrupt("offline crash after planning result committed")
        with patch.object(f, "agent", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            f.run("feature")
        self.assertEqual(f.row("feature")["status"], "PLAN")
        before = tuple(f.db.execute("SELECT * FROM operations WHERE stage='plan'").fetchone())
        self.assertEqual(f.run("feature")["DELIVERY_STATUS"], READY)
        self.assertEqual(tuple(f.db.execute("SELECT * FROM operations WHERE stage='plan'").fetchone()), before)
        self.assertEqual(sum(c["role"] == "plan" for c in f.runtime.calls), 1)

    def test_unknown_operation_never_replays_under_new_key_or_refunds_on_resume(self):
        self.config["budget"].update(max_run_tokens=240000, max_total_tokens=8400000)
        f = self.factory()
        def failed(*args):
            raise RuntimeFailure("offline partial failure", {"input_tokens": 100, "output_tokens": 1})
        with patch.object(f.runtime, "agent", side_effect=failed):
            self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        before = tuple(f.db.execute("SELECT * FROM operations").fetchone())
        budget = f.report("feature")["BUDGET_USED"]
        self.assertEqual(budget["unknown_token_reservation"], 240000)
        with patch("harness.factory_preflight.inspect_prepaid", side_effect=AssertionError("historical preflight forbidden")), \
             patch.object(f.runtime, "agent", side_effect=AssertionError("replay forbidden")):
            self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
            with self.assertRaises(FactoryBlocked):
                f.operation("feature", "new-key", "plan", "developer", {}, {}, True, lambda t: {})
        self.assertEqual(tuple(f.db.execute("SELECT * FROM operations").fetchone()), before)
        self.assertEqual(f.report("feature")["BUDGET_USED"], budget)

    def test_completed_planning_overrun_stops_before_implementation_and_retains_usage(self):
        self.config["budget"].update(max_run_tokens=240000, max_total_tokens=8400000)
        f = self.factory()
        with patch.object(f.runtime, "agent", return_value={"output": {}, "usage": {"input_tokens": 32001, "output_tokens": 0}}) as agent:
            report = f.run("feature")
            self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET")
            self.assertIn("planning token allowance exceeded", report["BLOCKERS_REMAINING"][0])
            self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "BLOCKED_BUDGET")
        self.assertEqual(agent.call_count, 1)
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 32001)
        self.assertEqual(report["BUDGET_USED"]["unknown_token_reservation"], 0)

    def test_partial_planning_cutoff_keeps_original_full_reservation_on_resume(self):
        self.config["budget"].update(max_run_tokens=240000, max_total_tokens=8400000)
        f = self.factory()
        with patch.object(f.runtime, "agent", side_effect=RuntimeFailure("offline planning cutoff", {"input_tokens": 32001, "output_tokens": 2})) as agent:
            report = f.run("feature")
            self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET")
            operation = f.db.execute("SELECT * FROM operations").fetchone()
            self.assertEqual(operation["status"], "UNKNOWN")
            before = tuple(operation)
            self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(agent.call_count, 1)
        self.assertEqual(tuple(f.db.execute("SELECT * FROM operations").fetchone()), before)
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 32003)
        self.assertEqual(report["BUDGET_USED"]["unknown_token_reservation"], 240000)
        self.assertEqual(f.report("feature")["BUDGET_USED"], report["BUDGET_USED"])

    def test_planner_receives_real_workspace_facts_and_required_contract(self):
        self.spec.update(acceptance=["Preserve existing behavior"],
                         constraints=["Never expand scope"], scope=["score.py"])
        f = self.factory()
        for remote in (False, True):
            with self.subTest(has_remotes=remote):
                mission = "remote-feature" if remote else "feature"
                if remote:
                    f.submit({**self.spec, "mission_id": mission})
                spec, cwd = f.prepare(mission)
                if remote:
                    git(cwd, "remote", "add", "fixture", str(self.repo))
                # A valid fixture plan stops at a product decision, allowing
                # inspection of the original agent path without implementation.
                result = {"output": {"plan": "offline inspection", "tasks": [], "acceptance": [],
                                     "decisions_required": ["offline control"]},
                          "usage": {"fixture_provider_calls": 0}}
                with patch.object(f.runtime, "agent", return_value=result) as agent:
                    self.assertEqual(f.run(mission)["DELIVERY_STATUS"], "WAITING_PRODUCT_DECISION")
                payload = agent.call_args.args[3]
                self.assertEqual(payload["workspace"], {
                    "base": spec["base"], "dispatch_head": git(cwd, "rev-parse", "HEAD"),
                    "branch": git(cwd, "rev-parse", "--abbrev-ref", "HEAD"),
                    "has_remotes": remote})
                for field in ("objective", "acceptance", "constraints", "scope"):
                    self.assertEqual(payload[field], spec[field])
                for rule in ("same version", "missing or changed", "nested rules", "authorization", "Batch independent"):
                    self.assertIn(rule, payload["execution_guidance"])

    def test_completed_plan_is_reused_after_checkpoint_changes_workspace_head(self):
        f = self.factory()
        spec, cwd = f.prepare("feature")
        before = git(cwd, "rev-parse", "HEAD")
        payload = {"objective": spec["objective"]}
        result = f.agent(spec, cwd, "plan", 0, payload)
        (cwd / "checkpoint.txt").write_text("offline checkpoint\n")
        self.assertNotEqual(f.checkpoint(spec, cwd)["head"], before)
        self.assertEqual(f.agent(spec, cwd, "plan", 0, payload), result)
        self.assertEqual(len(f.runtime.calls), 1)
        self.assertEqual(f.runtime.calls[0]["payload"]["workspace"]["dispatch_head"], before)

    def test_new_planning_policy_cannot_recover_old_unknown_but_new_mission_can_coexist(self):
        old_config = self.single_config()
        old_config["budget"].update(max_agent_runs=5, max_run_tokens=120000, max_total_tokens=600000)
        f = self.factory(old_config)
        with patch.object(f.runtime, "agent", side_effect=RuntimeFailure(
                "offline planning cutoff", {"input_tokens": 38268, "output_tokens": 347})):
            report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET")
        self.assertEqual(report["BUDGET_USED"]["committed_tokens"], 158615)
        snapshots = {table: [tuple(r) for r in f.db.execute(
            f"SELECT * FROM {table} WHERE {'id' if table == 'missions' else 'mission'}=?", ("feature",))]
            for table in ("missions", "operations", "events")}
        evidence = {p: p.read_bytes() for p in (self.root / "state" / "evidence" / "feature").iterdir() if p.is_file()}
        new_config = copy.deepcopy(f.config)
        new_config["budget"]["max_plan_tokens"] = 96000
        newer = Factory(self.root / "state", new_config, AcceptanceRuntime())
        self.addCleanup(newer.close)
        with self.assertRaisesRegex(ValueError, "immutable mission authority"):
            newer.run("feature")
        newer.submit({**self.spec, "mission_id": "independent-fixture"})
        fresh = newer.run("independent-fixture")
        self.assertEqual(fresh["DELIVERY_STATUS"], READY, fresh)
        self.assertEqual(fresh["BUDGET_USED"]["agent_runs"], 5)
        for value in (32000, 120000):
            newer.config["budget"]["max_plan_tokens"] = value
            with self.assertRaisesRegex(ValueError, "immutable mission authority"):
                newer.run("independent-fixture")
        newer.config["budget"]["max_plan_tokens"] = 96000
        for table, rows in snapshots.items():
            self.assertEqual([tuple(r) for r in f.db.execute(
                f"SELECT * FROM {table} WHERE {'id' if table == 'missions' else 'mission'}=?", ("feature",))], rows)
        self.assertEqual({p: p.read_bytes() for p in evidence}, evidence)
        with self.assertRaisesRegex(FactoryBlocked, "unresolved operation"):
            f.operation("feature", "new-fixture-key", "plan", "developer", {}, {}, True,
                        lambda t: self.fail("UNKNOWN cannot replay"))
        self.assertEqual(f.report("feature")["BUDGET_USED"]["unknown_token_reservation"], 120000)

    def test_explicit_planning_cutoff_retains_telemetry_unknown_and_full_reservation(self):
        self.config["budget"].update(max_plan_tokens=96000, max_run_tokens=120000, max_total_tokens=600000)
        f = self.factory()
        with patch.object(f.runtime, "agent", side_effect=RuntimeFailure(
                "offline planning cutoff", {"input_tokens": 96000, "output_tokens": 1})) as agent:
            report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET")
        self.assertEqual(agent.call_count, 1)
        self.assertEqual(f.db.execute("SELECT status FROM operations").fetchone()[0], "UNKNOWN")
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 96001)
        self.assertEqual(report["BUDGET_USED"]["unknown_token_reservation"], 120000)

    def test_completed_planning_with_explicit_allowance_exceeds_legacy_threshold(self):
        self.config["budget"].update(max_plan_tokens=96000, max_run_tokens=120000, max_total_tokens=600000)
        f = self.factory()
        result = {"output": {"plan": "offline plan", "tasks": [], "acceptance": [],
                             "decisions_required": ["offline control"]},
                  "usage": {"input_tokens": 38268, "output_tokens": 347}}
        with patch.object(f.runtime, "agent", return_value=result):
            report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "WAITING_PRODUCT_DECISION")
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 38615)
        self.assertEqual(report["BUDGET_USED"]["unknown_token_reservation"], 0)


class DockerHelpBoundaryTests(unittest.TestCase):
    def test_client_help_and_container_help_across_direct_shell_and_make_gates(self):
        cases = (
            ("docker --help", False),
            ("docker run --help", False),
            ("docker compose --help", False),
            ("docker compose exec --help", False),
            ("docker run --rm image tool --help", True),
            ("docker compose exec -T dev python3 -h", True),
            ("docker compose exec -T dev python3 --help", True),
            ("docker run --rm --help", False),
            ("docker run --name fixture --help", False),
            ("docker run --name fixture image tool --help", True),
            ("docker compose exec --index 2 --help", False),
            ("docker compose exec --index 2 dev python3 --help", True),
            ("docker run --name=fixture image tool --help", True),
            ("docker run -- image tool --help", True),
            ("docker exec -i container python3 --help", True),
            ("docker compose run --rm dev python3 --help", True),
        )
        spec = {"repository": "/unused", "base": "unused", "mission_id": "help-boundary"}
        for script, required in cases:
            with self.subTest(script=script):
                command = shlex.split(script)
                body = "verify:\n\t" + script + "\n"
                self.assertEqual(docker_gate(command), required)
                self.assertEqual(make_docker_dependency(body, ["make", "verify"]), required)
                for gate in (command, ["bash", "-lc", script], ["make", "verify"]):
                    config = {"simulation": True, "independent_review_required": False,
                              "checks": [gate], "ci": []}
                    with patch("harness.factory_preflight.shutil.which", return_value="/usr/bin/fixture"), \
                         patch("harness.factory_preflight.committed_text", return_value=body):
                        report = inspect_prepaid(spec, config)
                    self.assertEqual(report["status"], "HARD_BLOCKER" if required else "NO_KNOWN_HARD_BLOCKER")
                    self.assertEqual(any(x["level"] == "HARD_BLOCKER" and "Docker-dependent" in x["detail"]
                                         for x in report["findings"]), required)

    def test_unknown_option_arity_does_not_guess_help_boundary(self):
        for script in ("docker run --unknown value --help", "docker compose exec --unknown value --help"):
            with self.subTest(script=script):
                self.assertFalse(docker_gate(shlex.split(script)))
                config = {"simulation": True, "independent_review_required": False,
                          "checks": [["bash", "-lc", script]], "ci": []}
                report = inspect_prepaid({"repository": "/unused", "base": "unused"}, config)
                self.assertEqual(report["status"], "NO_KNOWN_HARD_BLOCKER")
                self.assertTrue(any(x["check"] == "checks[0]" and x["level"] == "UNVERIFIED"
                                    for x in report["findings"]))


class WorkflowTriggerTests(unittest.TestCase):
    def test_tag_only_push_excludes_candidates_even_with_path_filters(self):
        for body in ("tags: ['v*']", "tags-ignore: ['old-*']", "tags: ['v*']\n    paths: ['src/**']"):
            with self.subTest(body=body):
                self.assertEqual(workflow_push("on:\n  push:\n    " + body + "\n", "factory/feature-")[0], "HARD_BLOCKER")

    def test_mixed_branch_and_tag_filters_do_not_falsely_exclude_candidates(self):
        for body in ("branches: ['factory/**']\n    tags: ['v*']",
                     "branches-ignore: [main]\n    tags: ['v*']",
                     "branches: ['factory/feature-exact']\n    tags-ignore: ['v*']"):
            with self.subTest(body=body):
                self.assertEqual(workflow_push("on:\n  push:\n    " + body + "\n", "factory/feature-")[0], "UNVERIFIED")
        self.assertEqual(workflow_push("on:\n  push:\n    branches: [main]\n    tags: ['v*']\n", "factory/feature-")[0], "HARD_BLOCKER")

    def test_malformed_tag_filters_are_unverified(self):
        for body in ("tags: null", "tags: []", "tags: v*", "tags: [true]", "tags: ['v*']\n    tags-ignore: ['old-*']"):
            with self.subTest(body=body):
                self.assertEqual(workflow_push("on:\n  push:\n    " + body + "\n", "factory/feature-")[0], "UNVERIFIED")

    def test_known_no_push_and_literal_exclusions(self):
        for text in ("on: [pull_request]\n", "on:\n  workflow_dispatch:\n", "on:\n  push:\n    branches: [main, release]\n"):
            self.assertEqual(workflow_push(text, "factory/feature-")[0], "HARD_BLOCKER")

    def test_push_support_is_only_a_warning_not_a_qualification(self):
        for text in ("on: push\n", "on: [push, pull_request]\n", '"on":\n  push:\n'):
            self.assertEqual(workflow_push(text, "factory/feature-")[0], "WARNING")

    def test_filters_malformed_and_unknown_yaml_are_unverified(self):
        for text in ("on:\n  push:\n    paths: ['src/**']\n", "on:\n  push:\n    branches: ['factory/**']\n", "on: [push\n", "name: unknown\n", "on:\n  push: false\n", "on: push\non: pull_request\n", "on:\n  push:\n    unknown: true\n", "on: [{push: null}]\n"):
            self.assertEqual(workflow_push(text, "factory/feature-")[0], "UNVERIFIED")


class PlanningGuardTests(unittest.TestCase):
    def test_planning_limits_only_reduce_existing_authority(self):
        self.assertEqual(planning_limits({"max_run_tokens": 240000}, 900), {"max_tokens": 32000, "timeout_seconds": 120})
        self.assertEqual(planning_limits({"max_run_tokens": 100}, 3), {"max_tokens": 100, "timeout_seconds": 3})
        self.assertEqual(planning_limits({"max_run_tokens": 120000, "max_plan_tokens": 96000}, 900),
                         {"max_tokens": 96000, "timeout_seconds": 120})

    def test_explicit_planning_budget_validation_and_legacy_config_compatibility(self):
        config = fixture_config()
        self.assertNotIn("max_plan_tokens", validate_config(config)["budget"])
        config["budget"].update(max_run_tokens=120000, max_total_tokens=600000)
        for value in (1, 96000, 120000):
            with self.subTest(valid=value):
                config["budget"]["max_plan_tokens"] = value
                self.assertEqual(validate_config(config)["budget"]["max_plan_tokens"], value)
        for value in (True, False, 0, -1, 96000.0, "96000", None, [], {}, 120001):
            with self.subTest(invalid=value):
                config["budget"]["max_plan_tokens"] = value
                with self.assertRaises(ValueError):
                    validate_config(config)
        legacy = fixture_config()
        legacy["budget"]["max_plan_tokens"] = 1
        with self.assertRaisesRegex(ValueError, "max_run_tokens"):
            validate_config(legacy)

    def test_runtime_applies_planning_limits_to_native_watchdog_and_proxy_observer(self):
        runtime = LocalRuntime()
        runtime.resource_policy = {"max_run_tokens": 240000}
        server = Mock()
        server.execute.return_value = {"output": {}}
        server.proc = None
        with patch("harness.factory_runtime.FactoryAppServer", return_value=server) as constructor:
            runtime.agent("plan", {}, Path("/fixture"), {"objective": "fixture"}, Path("/fixture.raw"), 900, [])
        args = constructor.call_args.args
        self.assertEqual(args[3], 120)
        self.assertEqual(args[-1], 32000)
        prompt = json.loads(server.execute.call_args.args[0])
        self.assertEqual(prompt["planning_resource_guard"]["physical_token_ceiling"], "NOT_GUARANTEED")
        runtime.resource_policy.update(max_plan_tokens=96000)
        with patch("harness.factory_runtime.FactoryAppServer", return_value=server) as constructor:
            runtime.agent("plan", {}, Path("/fixture"), {"objective": "fixture"}, Path("/fixture.raw"), 900, [])
        self.assertEqual(constructor.call_args.args[3], 120)
        self.assertEqual(constructor.call_args.args[-1], 96000)
        guard = json.loads(server.execute.call_args.args[0])["planning_resource_guard"]
        self.assertEqual(guard["max_tokens"], 96000)
        self.assertIn("cached input once", guard["instruction"])
        runtime.resource_policy = {"max_run_tokens": 12, "max_first_turn_tokens": 60000,
                                  "max_repair_incremental_tokens": 36000}
        with patch("harness.factory_runtime.FactoryAppServer", return_value=server) as constructor:
            runtime.agent("implement", {}, Path("/fixture"), {}, Path("/fixture.raw"), 9, [])
        self.assertEqual(constructor.call_args.args[3], 9)
        self.assertEqual(constructor.call_args.args[-1], 12)

    def test_foreign_thread_telemetry_cannot_charge_or_interrupt_active_turn(self):
        server = FactoryAppServer.__new__(FactoryAppServer)
        server.events, server.token_limit, server.runtime_identity = [], 32000, {}
        server._bind_usage_thread("t")
        server._bind_usage_turn("u")
        usage = {"total": {"inputTokens": 32001, "outputTokens": 0, "totalTokens": 32001}}
        with patch("harness.codex.AppServerCodex._read_message", return_value={"method": "thread/tokenUsage/updated", "params": {"threadId": "t", "turnId": "u", "tokenUsage": usage}}):
            with self.assertRaises(RuntimeFailure) as failure:
                server._read_message()
        self.assertEqual(failure.exception.usage, usage)
        self.assertFalse(failure.exception.usage_complete)


if __name__ == "__main__":
    unittest.main()

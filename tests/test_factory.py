from __future__ import annotations

import copy
import fcntl
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, READY, git, validate_config, validate_mission, review_verdict, observed_usage
from harness.factory_fixture import AcceptanceRuntime, fixture_config, demo
from harness.factory_runtime import FactoryAppServer, LocalRuntime, RuntimeFailure, official_rubric, REVIEW_SCHEMA, validate_openai_route
from harness.factory_cli import main as factory_cli


class FactoryAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "score.py").write_text("def add(a, b):\n    return a + b\n")
        (self.repo / "historical-UNKNOWN.json").write_text('{"status":"UNKNOWN","usage":null}\n')
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost", "commit", "-qm", "baseline")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.config = fixture_config()
        self.runtime = AcceptanceRuntime()
        self.factory = Factory(self.root / "state", self.config, self.runtime)
        self.addCleanup(lambda: self.factory.close())
        self.spec = {"version": 2, "mission_id": "feature", "repository": str(self.repo),
                     "objective": "Add average(values), preserving fractional results, empty input and add.",
                     "acceptance": ["average([1,2]) == 1.5", "average([]) == 0", "add(2,3) == 5"]}
        self.factory.submit(self.spec)

    def ready(self):
        report = self.factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        return report

    def reopen(self, config=None, runtime=None):
        self.factory.close()
        self.runtime = runtime or AcceptanceRuntime()
        self.factory = Factory(self.root / "state", config or self.config, self.runtime)

    def test_product_request_to_real_code_tests_independent_findings_rework_and_delivery(self):
        report = self.ready()
        stages = [r[0] for r in self.factory.db.execute("SELECT stage FROM operations ORDER BY started")]
        self.assertEqual(stages, ["plan", "implement", "checks", "ci", "review", "review", "rework", "checks", "ci", "review", "review"])
        self.assertEqual(report["TEST_RESULT"], "PASS")
        self.assertEqual(report["CI_RESULT"], "PASS")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 7)
        self.assertEqual({r["provider"] for r in report["REVIEW_RESULT"]}, {"openai", "deepseek"})
        self.assertFalse(report["MERGE_PERFORMED"])
        self.assertNotEqual(report["TARGET_HEAD"], self.base)
        self.assertTrue((Path(report["CANDIDATE"]) / "tests/test_score.py").is_file())
        self.assertIn("test_fractional", (Path(report["CANDIDATE"]) / "tests/test_score.py").read_text())

    def test_multiple_planned_tasks_get_separate_official_agent_dispatches(self):
        original = self.runtime.agent
        def agent(role, *args):
            result = original(role, *args)
            if role == "plan":
                result["output"]["tasks"].append("Check documented acceptance behavior")
            return result
        with patch.object(self.runtime, "agent", side_effect=agent):
            report = self.ready()
        implementations = [call for call in self.runtime.calls if call["role"] == "implement"]
        self.assertEqual(len(implementations), 2)
        self.assertNotEqual(implementations[0]["payload"]["current_task"], implementations[1]["payload"]["current_task"])
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 8)

    def test_genuine_product_decision_stops_before_implementation(self):
        original = self.runtime.agent
        def agent(role, *args):
            result = original(role, *args)
            result["output"]["decisions_required"] = ["Choose whether empty input means zero or missing data"]
            return result
        with patch.object(self.runtime, "agent", side_effect=agent):
            report = self.factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "WAITING_PRODUCT_DECISION")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 1)

    def test_optional_committed_mission_contract_is_immutable(self):
        (self.repo / "scope.json").write_text('{"allowed":"source-only"}\n')
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "scope authority")
        spec = {**self.spec, "mission_id": "contract", "mission_scope_file": "scope.json"}
        self.factory.submit(spec)
        persisted, cwd = self.factory.prepare("contract")
        target = self.factory.target(persisted, cwd)
        self.assertEqual(target["mission_scope_file"], "scope.json")
        (cwd / "scope.json").write_text('{"allowed":"everything"}\n')
        with self.assertRaises(FactoryBlocked) as error:
            self.factory.checkpoint(persisted, cwd)
        self.assertEqual(error.exception.status, "BLOCKED_SCOPE")

    def test_independent_lane_never_receives_first_lane_findings_or_plan(self):
        self.ready()
        calls = [call for call in self.runtime.calls if call["role"] == "review"]
        self.assertEqual(len(calls), 4)
        for call in calls:
            self.assertNotIn("feedback", call["payload"])
            self.assertNotIn("plan", call["payload"])
            self.assertNotIn("findings", call["payload"])
        self.assertNotEqual(calls[0]["payload"]["review_root"], calls[1]["payload"]["review_root"])
        self.assertEqual(calls[0]["payload"]["target"], calls[1]["payload"]["target"])
        self.assertIn("repository_context", calls[1]["payload"])

    def test_original_git_and_historical_unknown_remain_byte_identical(self):
        before = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob("*") if p.is_file()}
        self.ready()
        after = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        self.assertFalse((self.repo / "average.py").exists())

    def test_resume_ready_makes_no_new_engine_or_test_dispatch(self):
        report = self.ready()
        count = self.factory.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        self.reopen()
        self.assertEqual(self.factory.run("feature")["TARGET_HEAD"], report["TARGET_HEAD"])
        self.assertEqual(len(self.runtime.calls), 0)
        self.assertEqual(self.factory.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], count)

    def test_openai_model_switch_only_refreshes_openai_review_evidence(self):
        first = self.ready()
        old_second = [r for r in first["REVIEW_RESULT"] if r["provider"] == "deepseek"][0]
        config = copy.deepcopy(self.config)
        config["profiles"]["reviewer"]["model"] = "fixture-new-openai"
        self.reopen(config)
        self.assertEqual(self.factory.report("feature")["DELIVERY_STATUS"], "PENDING_REVIEW")
        second = self.ready()
        self.assertEqual(second["BUDGET_USED"]["agent_runs"], 8)
        self.assertEqual([r for r in second["REVIEW_RESULT"] if r["provider"] == "deepseek"][0], old_second)
        self.assertEqual([(r["role"], r["provider"]) for r in self.runtime.calls], [("review", "openai")])

    def test_completed_delivery_survives_unrelated_developer_model_switch(self):
        report = self.ready()
        config = copy.deepcopy(self.config)
        config["profiles"]["developer"]["model"] = "fixture-new-developer"
        self.reopen(config)
        current = self.ready()
        self.assertEqual(current["TARGET_HEAD"], report["TARGET_HEAD"])
        self.assertEqual(self.runtime.calls, [])

    def test_hybrid_official_home_change_only_refreshes_that_lane_after_restart(self):
        config = copy.deepcopy(self.config)
        config["profiles"]["developer"]["transport"] = {"type": "cli_proxy", "endpoint": "http://127.0.0.1:18317/v1",
            "configured_provider": "cli_proxy_api", "policy_file": "/fixture/private-policy.json"}
        config["profiles"]["reviewer"].update(transport={"type": "official"}, codex_home="/fixture/official-home-a")
        config["profiles"]["second_reviewer"]["transport"] = {"type": "direct"}
        self.reopen(config)
        first = self.ready()
        original_receipts = {r["id"]: Path(r["evidence"]).read_bytes() for r in self.factory.db.execute("SELECT * FROM operations")}
        changed = copy.deepcopy(config)
        changed["profiles"]["reviewer"]["codex_home"] = "/fixture/official-home-b"
        self.reopen(changed)
        second = self.ready()
        self.assertEqual([(c["role"], c["provider"]) for c in self.runtime.calls], [("review", "openai")])
        self.assertEqual(first["REVIEW_RESULT"][1], second["REVIEW_RESULT"][1])
        for row in self.factory.db.execute("SELECT * FROM operations"):
            if row["id"] in original_receipts:
                self.assertEqual(Path(row["evidence"]).read_bytes(), original_receipts[row["id"]])

    def test_hybrid_official_reviewer_failure_is_unknown_without_proxy_replay(self):
        config = copy.deepcopy(self.config)
        config["budget"].update(max_run_tokens=100, max_total_tokens=1200)
        config["profiles"]["developer"]["transport"] = {"type": "cli_proxy", "endpoint": "http://127.0.0.1:18317/v1",
            "configured_provider": "cli_proxy_api", "policy_file": "/fixture/private-policy.json"}
        config["profiles"]["reviewer"]["transport"] = {"type": "official"}
        self.factory.close()
        self.runtime = AcceptanceRuntime()
        self.factory = Factory(self.root / "hybrid-failure-state", config, self.runtime)
        self.factory.submit(self.spec)
        original = self.runtime.agent
        def fail_reviewer(role, *args):
            if role == "review":
                raise RuntimeFailure("official access denied", {"input_tokens": 2, "output_tokens": 1})
            return original(role, *args)
        with patch.object(self.runtime, "agent", side_effect=fail_reviewer) as dispatch:
            result = self.factory.run("feature")
            self.assertEqual(result["DELIVERY_STATUS"], "UNKNOWN")
            count = dispatch.call_count
            self.factory.run("feature")
            self.assertEqual(dispatch.call_count, count)
        self.assertEqual(result["BUDGET_USED"]["partial_usage_runs"], 1)
        self.assertEqual(result["BUDGET_USED"]["unknown_token_reservation"], 100)
        self.assertEqual(self.factory.db.execute("SELECT COUNT(*) FROM operations WHERE lane='second_reviewer'").fetchone()[0], 0)

    def test_deepseek_model_switch_preserves_openai_review(self):
        first = self.ready()
        config = copy.deepcopy(self.config)
        config["profiles"]["second_reviewer"]["model"] = "fixture-new-second"
        self.reopen(config)
        second = self.ready()
        self.assertEqual(second["BUDGET_USED"]["agent_runs"], 8)
        self.assertEqual([(r["role"], r["provider"]) for r in self.runtime.calls], [("review", "deepseek")])
        self.assertEqual(first["REVIEW_RESULT"][0], second["REVIEW_RESULT"][0])

    def test_dirty_delivery_cannot_remain_ready_even_through_status(self):
        report = self.ready()
        (Path(report["CANDIDATE"]) / "score.py").write_text("uncommitted corruption\n")
        self.assertEqual(self.factory.report("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.factory.run("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_committed_head_change_invalidates_delivery(self):
        report = self.ready()
        cwd = Path(report["CANDIDATE"])
        (cwd / "another.txt").write_text("new unreviewed change\n")
        git(cwd, "add", ".")
        git(cwd, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "unreviewed")
        self.assertEqual(self.factory.report("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_hashed_evidence_corruption_blocks_resume_without_paid_replay(self):
        report = self.ready()
        Path(report["DELIVERY_EVIDENCE"][-1]).chmod(0o600)
        Path(report["DELIVERY_EVIDENCE"][-1]).write_text("corrupt")
        self.reopen()
        self.assertEqual(self.factory.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.runtime.calls, [])

    def test_raw_evidence_corruption_blocks_delivery(self):
        self.ready()
        row = self.factory.db.execute("SELECT result FROM operations WHERE stage='review' ORDER BY started DESC LIMIT 1").fetchone()
        path = Path(json.loads(row[0])["raw_evidence"][0]["path"])
        path.write_text("altered raw provider response")
        self.assertEqual(self.factory.report("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_missing_evidence_cannot_be_pass(self):
        report = self.ready()
        Path(report["DELIVERY_EVIDENCE"][-1]).unlink()
        self.assertEqual(self.factory.report("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_scope_violation_stops_before_tests_or_review(self):
        # Scope is customer authority, not an internal model suggestion.
        self.factory.submit({**self.spec, "mission_id": "narrow", "scope": ["score.py"]})
        report = self.factory.run("narrow")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_SCOPE")
        self.assertEqual([r[0] for r in self.factory.db.execute("SELECT stage FROM operations WHERE mission='narrow' ORDER BY started")], ["plan", "implement"])

    def test_budget_exhaustion_counts_all_dispatches_and_stops(self):
        config = copy.deepcopy(self.config)
        config["budget"]["max_agent_runs"] = 3
        small = Factory(self.root / "limited", config, AcceptanceRuntime())
        self.addCleanup(small.close)
        small.submit(self.spec)
        report = small.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 3)
        self.assertEqual(report["REVIEW_RESULT"], "UNKNOWN")

    def test_failure_consumes_reservation_and_unknown_usage_is_not_zero(self):
        with patch.object(self.runtime, "agent", side_effect=RuntimeFailure("connection lost")):
            report = self.factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 1)
        self.assertEqual(report["BUDGET_USED"]["unknown_usage_runs"], 1)
        row = self.factory.db.execute("SELECT status,usage FROM operations").fetchone()
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertIsNone(row["usage"])
        self.reopen()
        self.assertEqual(self.factory.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.runtime.calls, [])

    def test_failed_runtime_preserves_observed_usage_without_refund(self):
        usage = {"input_tokens": 41, "output_tokens": 9}
        with patch.object(self.runtime, "agent", side_effect=RuntimeFailure("failed after usage", usage)):
            report = self.factory.run("feature")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 1)
        self.assertEqual(report["BUDGET_USED"]["unknown_usage_runs"], 0)
        self.assertEqual(json.loads(self.factory.db.execute("SELECT usage FROM operations").fetchone()[0]), usage)

    def test_crash_with_running_reservation_does_not_reissue_paid_turn(self):
        with patch.object(self.runtime, "agent", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.factory.run("feature")
        self.assertEqual(self.factory.db.execute("SELECT status FROM operations").fetchone()[0], "RUNNING")
        self.reopen()
        report = self.factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 1)
        self.assertEqual(self.runtime.calls, [])

    def test_crash_after_implementation_recovers_checkpoint_without_repeating_it(self):
        with patch.object(self.factory, "checkpoint", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.factory.run("feature")
        self.reopen()
        report = self.ready()
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 7)
        self.assertNotIn("implement", [r["role"] for r in self.runtime.calls])

    def test_concurrent_controller_does_not_execute_or_mutate_state(self):
        lock = self.root / "state/control/feature.lock"
        with lock.open("w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            report = self.factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "RUNNING")
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.factory.row("feature")["status"], "CREATED")

    def test_test_failure_is_automatically_reworked_before_review(self):
        original = self.runtime.gate
        failed = [False]
        def gate(command, cwd, target, transcript, timeout):
            if command[1:3] == ["-m", "unittest"] and not failed[0]:
                failed[0] = True
                transcript.write_text("ordinary regression failure")
                return {"status": "FAIL", "exit_code": 1, "log": "ordinary regression failure"}
            return original(command, cwd, target, transcript, timeout)
        with patch.object(self.runtime, "gate", side_effect=gate):
            self.ready()
        self.assertEqual([r["role"] for r in self.runtime.calls], ["plan", "implement", "rework", "review", "review"])
        self.assertEqual(self.runtime.calls[2]["payload"]["feedback"][0]["department"], "test")

    def test_ci_failure_enters_automatic_rework(self):
        original = self.runtime.gate
        failed = [False]
        def gate(command, cwd, target, transcript, timeout):
            if "compileall" in command and not failed[0]:
                failed[0] = True
                transcript.write_text("CI failed")
                return {"status": "FAIL", "exit_code": 2, "log": "CI failed"}
            return original(command, cwd, target, transcript, timeout)
        with patch.object(self.runtime, "gate", side_effect=gate):
            self.ready()
        self.assertEqual(self.runtime.calls[2]["payload"]["feedback"][0]["department"], "ci")

    def test_gate_unknown_or_contradictory_exit_is_not_pass(self):
        for result in ({"status": "PASS"}, {"status": "PASS", "exit_code": 1}, {"status": "UNKNOWN", "exit_code": 0}):
            with self.subTest(result=result):
                isolated = Factory(self.root / uuid_path(), self.config, AcceptanceRuntime())
                try:
                    isolated.submit(self.spec)
                    with patch.object(isolated.runtime, "gate", return_value=result):
                        self.assertEqual(isolated.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
                finally:
                    isolated.close()

    def test_gate_source_mutation_is_not_pass(self):
        def bad_gate(command, cwd, target, transcript, timeout):
            (cwd / "score.py").write_text("mutated by test process")
            return {"status": "PASS", "exit_code": 0}
        with patch.object(self.runtime, "gate", side_effect=bad_gate):
            self.assertEqual(self.factory.run("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_completed_malformed_review_has_bounded_fresh_recovery(self):
        original = self.runtime.agent
        failed = [False]
        def agent(role, *args):
            if role == "review" and not failed[0]:
                failed[0] = True
                return {"output": {"findings": []}, "usage": None}
            return original(role, *args)
        with patch.object(self.runtime, "agent", side_effect=agent):
            report = self.ready()
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 8)
        self.assertEqual(report["BUDGET_USED"]["unknown_usage_runs"], 1)

    def test_repeated_malformed_review_never_becomes_pass(self):
        original = self.runtime.agent
        def agent(role, *args):
            if role == "review":
                return {"output": {"findings": []}}
            return original(role, *args)
        with patch.object(self.runtime, "agent", side_effect=agent):
            report = self.factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 4)

    def test_rework_limit_is_bounded_without_delivery_pass(self):
        config = copy.deepcopy(self.config)
        config["max_rounds"] = 1
        limited = Factory(self.root / "round-limit", config, AcceptanceRuntime())
        self.addCleanup(limited.close)
        limited.submit(self.spec)
        report = limited.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_LIMIT")
        self.assertEqual(report["TEST_RESULT"], "UNKNOWN")

    def test_oversized_full_diff_stops_without_chunking_or_truncation(self):
        config = copy.deepcopy(self.config)
        config["max_review_bytes"] = 10
        limited = Factory(self.root / "diff-limit", config, AcceptanceRuntime())
        self.addCleanup(limited.close)
        limited.submit(self.spec)
        report = limited.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_SCOPE")
        self.assertIn("nothing was truncated", report["BLOCKERS_REMAINING"][0])

    def test_full_second_provider_context_limit_cannot_silently_truncate(self):
        config = copy.deepcopy(self.config)
        config["max_context_bytes"] = 10
        limited = Factory(self.root / "context-limit", config, AcceptanceRuntime())
        self.addCleanup(limited.close)
        limited.submit(self.spec)
        report = limited.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_PREFLIGHT")
        self.assertEqual(report["BUDGET_USED"]["agent_runs"], 0)
        self.assertIn("nothing was truncated", report["BLOCKERS_REMAINING"][0])

    def test_immutable_budget_authority_cannot_be_increased_on_resume(self):
        config = copy.deepcopy(self.config)
        config["budget"]["max_agent_runs"] = 20
        self.reopen(config)
        with self.assertRaisesRegex(ValueError, "immutable mission authority"):
            self.factory.run("feature")

    def test_independence_requirement_cannot_be_removed_from_existing_mission(self):
        config = copy.deepcopy(self.config)
        config["independent_review_required"] = False
        del config["profiles"]["second_reviewer"]
        self.reopen(config)
        with self.assertRaises(ValueError):
            self.factory.run("feature")

    def test_completed_accounting_and_unknown_cannot_be_rewritten_or_deleted(self):
        with patch.object(self.runtime, "agent", side_effect=RuntimeFailure("timeout")):
            self.factory.run("feature")
        with self.assertRaises(sqlite3.IntegrityError):
            self.factory.db.execute("UPDATE operations SET usage='0',status='COMPLETE'")
        self.factory.db.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.factory.db.execute("DELETE FROM operations")
        self.factory.db.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.factory.db.execute("UPDATE events SET kind='fake-pass'")

    def test_mission_spec_cannot_be_mutated(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.factory.db.execute("UPDATE missions SET spec='{}'")
        self.factory.db.rollback()
        with self.assertRaises(ValueError):
            self.factory.submit({**self.spec, "objective": "something different"})

    def test_fixture_cannot_obtain_merge_approval_or_trigger_merge(self):
        report = self.ready()
        with self.assertRaises(ValueError):
            self.factory.approve("feature", "merge", "approved", report["TARGET_HEAD"])
        self.assertEqual(self.factory.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0], 0)

    def test_factory_state_must_not_be_inside_customer_repository(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            Factory(self.repo / "factory-state", self.config, AcceptanceRuntime())
        self.assertFalse((self.repo / "factory-state").exists())

    def test_database_symlink_is_rejected(self):
        attack = self.root / "attack/control"
        attack.mkdir(parents=True)
        (attack / "factory.sqlite").symlink_to(self.repo / "historical-UNKNOWN.json")
        with self.assertRaises(ValueError):
            Factory(attack.parent, self.config, AcceptanceRuntime())

    def test_simulation_live_runtime_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            Factory(self.root / "wrong", self.config, LocalRuntime())

    def test_same_provider_second_opinion_is_rejected(self):
        config = copy.deepcopy(self.config)
        config["profiles"]["second_reviewer"]["provider"] = "openai"
        with self.assertRaisesRegex(ValueError, "different providers"):
            validate_config(config)

    def test_invalid_config_values_and_scope_fail_closed(self):
        for change in ({"max_rounds": True}, {"timeout_seconds": 0}, {"checks": []}, {"ci": [[""]]}, {"budget": {"max_agent_runs": True}}, {"independent_review_required": "false"}, {"unknown": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_config({**self.config, **change})
        for scope in (["../outside"], ["/absolute"], []):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                validate_mission({**self.spec, "scope": scope})

    def test_finding_wrong_commit_file_or_line_is_rejected(self):
        self.factory.prepare("feature")
        cwd = Path(self.factory.row("feature")["candidate"])
        self.runtime.agent("implement", self.config["profiles"]["developer"], cwd, {}, self.root / "fake.raw", 30, [])
        target = self.factory.checkpoint(validate_mission(self.spec), cwd)
        finding = AcceptanceRuntime.review_output(cwd, {"target": target})
        review_verdict(finding, cwd, target)
        for modify in (lambda f: f["findings"][0]["code_location"].update(absolute_file_path=str(self.repo / "score.py")),
                       lambda f: f["findings"][0]["code_location"]["line_range"].update(start=500, end=500),
                       lambda f: f["findings"][0]["code_location"].update(absolute_file_path=str(cwd / "historical-UNKNOWN.json")),
                       lambda f: f.update(overall_correctness="patch is correct")):
            bad = copy.deepcopy(finding)
            modify(bad)
            with self.assertRaises(ValueError):
                review_verdict(bad, cwd, target)

    def test_deleted_file_finding_verifies_base_blob_and_delivery_head(self):
        spec, cwd = self.factory.prepare("feature")
        (cwd / "score.py").unlink()
        target = self.factory.checkpoint(spec, cwd)
        output = {"findings": [{"title": "[P1] Preserve existing add", "body": "Deleting add breaks existing callers.",
                                "confidence_score": 1, "priority": 1,
                                "code_location": {"absolute_file_path": str(cwd / "score.py"), "line_range": {"start": 1, "end": 2}}}],
                  "overall_correctness": "patch is incorrect", "overall_explanation": "Existing public function is removed.", "overall_confidence_score": 1}
        status, findings = review_verdict(output, cwd, target)
        self.assertEqual(status, "FAIL")
        self.assertEqual(findings[0]["source"]["commit"], self.base)
        self.assertEqual(findings[0]["source"]["target_head"], target["head"])


def uuid_path():
    import uuid
    return uuid.uuid4().hex


class FactoryRuntimeTests(unittest.TestCase):
    def test_empty_or_invalid_usage_remains_unknown_without_guessing_zero(self):
        for value in (None, {}, 0, "0", {"input_tokens": True, "output_tokens": 0}, {"prompt_tokens": -1, "completion_tokens": 2}):
            self.assertIsNone(observed_usage(value))
        self.assertEqual(observed_usage({"input_tokens": 4, "output_tokens": 2}), {"input_tokens": 4, "output_tokens": 2})
        self.assertIsNone(observed_usage({"fixture_provider_calls": 0}))
    def test_provider_name_cannot_masquerade_as_openai_with_other_endpoint(self):
        validate_openai_route({"model_providers": {"openai": {"base_url": "https://api.openai.com/v1"}}})
        validate_openai_route({"chatgpt_base_url": "https://chatgpt.com/backend-api"})
        with self.assertRaisesRegex(ValueError, "identity is unproven"):
            validate_openai_route({"model_providers": {"openai": {"base_url": "https://api.deepseek.com/v1"}}})

    def test_streamed_items_and_usage_are_retained_even_if_completion_items_are_empty(self):
        server = FactoryAppServer.__new__(FactoryAppServer)
        server._policy_cwd = "/tmp/fixture"
        server._forbidden_actions = ("merge",)
        server._permissions_profile = "fixture"
        server.MODEL = "fixture-model"
        server.REASONING_EFFORT = None
        server.runtime_identity = {"model": "fixture-model", "provider": "openai"}
        usage = {"last": {"totalTokens": 21}, "total": {"totalTokens": 21}}
        server.usage = None
        server.events = [
            {"method": "item/completed", "params": {"threadId": "t", "turnId": "u", "item": {"id": "final", "type": "agentMessage", "phase": "final_answer", "text": '{"answer":"ok"}'}}},
            {"method": "thread/tokenUsage/updated", "params": {"threadId": "t", "turnId": "u", "tokenUsage": usage}},
        ]
        server.token_limit = 100
        def complete(*args):
            for event in server.events:
                server._observe_execution_event(event)
            return {"items": []}
        with patch.object(server, "start_or_resume", return_value="t"), patch.object(server, "_request", return_value={"turn": {"id": "u"}}) as request, patch.object(server, "_turn_completed", side_effect=complete):
            result = server.execute("fixture input", {"type": "object"})
        self.assertEqual(result["output"], {"answer": "ok"})
        self.assertEqual(result["usage"], usage)
        self.assertIn("outputSchema", request.call_args.args[1])

    def test_malformed_wire_output_is_preserved_verbatim_before_json_failure(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            server = FactoryAppServer.__new__(FactoryAppServer)
            server.proc = SimpleNamespace(stdout=io.StringIO(' malformed JSON }\n'))
            server.transcript = Path(temporary) / "raw"
            server._transcript_bytes = 0
            server._reader_thread = None
            with patch.object(server, "close"), self.assertRaisesRegex(RuntimeError, "malformed JSON"):
                server._read_message()
            self.assertEqual(server.transcript.read_text(), ' malformed JSON }\n')

    def test_native_project_trust_bookkeeping_does_not_change_model_profile_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            config = home / "config.toml"
            config.write_text('model="same-model"\n')
            profile = {"provider": "openai", "codex_home": str(home)}
            with patch("harness.factory_runtime.subprocess.check_output", return_value="codex fixture"), patch("harness.factory_runtime.AppServerCodex._trusted_executable", return_value=Path("/usr/bin/true")):
                before = LocalRuntime().profile_identity(profile)
                config.write_text('model="same-model"\n[projects."/another/candidate"]\ntrust_level="trusted"\n')
                after = LocalRuntime().profile_identity(profile)
                self.assertEqual(before, after)
                config.write_text('model="new-model"\n')
                self.assertNotEqual(before, LocalRuntime().profile_identity(profile))

    def test_official_rubric_is_unmodified_with_pinned_provenance(self):
        self.assertIn("# Review guidelines:", official_rubric())
        self.assertIn("overall_correctness", official_rubric())
        self.assertEqual(REVIEW_SCHEMA["properties"]["overall_correctness"]["enum"], ["patch is correct", "patch is incorrect"])

    def test_deepseek_actual_adapter_records_usage_and_checks_model_and_finish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = root / "token"
            token.write_text("fixture-secret-never-a-real-key")
            token.chmod(0o600)
            profile = {"provider": "deepseek", "model": "deepseek-chat", "token_file": str(token)}
            body = {"id": "fixture", "model": "deepseek-chat", "usage": {"prompt_tokens": 12, "completion_tokens": 8},
                    "choices": [{"finish_reason": "stop", "message": {"content": json.dumps({"findings": []})}}]}
            def response():
                return io.BytesIO(json.dumps(body).encode())
            from harness.factory_http import request
            from unittest.mock import Mock
            opener = Mock()
            opener.open.side_effect = lambda *a, **k: response()
            with patch("urllib.request.build_opener", return_value=opener):
                transport = opener.open
                result = request(profile, {"diff": "full diff", "target": {}}, root / "review.raw", 30)
            self.assertEqual(result["usage"], body["usage"])
            self.assertEqual(result["runtime_identity"]["route_identity"]["route_type"], "direct")
            self.assertEqual(result["runtime_identity"]["reported_model"], "deepseek-chat")
            self.assertEqual(len(result["runtime_identity"]["qualification_identity"]), 64)
            sent = json.loads(transport.call_args.args[0].data)
            self.assertIn("# Review guidelines:", sent["messages"][0]["content"])
            self.assertNotIn(token.read_text(), (root / "review.raw").read_text())
            for field, value in (("model", "another-model"), ("choices", [{"finish_reason": "length", "message": {"content": "{}"}}])):
                changed = copy.deepcopy(body)
                changed[field] = value
                opener.open.side_effect = None
                opener.open.return_value = io.BytesIO(json.dumps(changed).encode())
                with patch("urllib.request.build_opener", return_value=opener):
                    failed = request(profile, {}, root / "bad.raw", 30)
                self.assertIn("error", failed)
                self.assertEqual(failed["usage"], body["usage"])
            changed = {**body, "usage": None}
            opener.open.return_value = io.BytesIO(json.dumps(changed).encode())
            with patch("urllib.request.build_opener", return_value=opener):
                missing_usage = request(profile, {}, root / "missing-usage.raw", 30)
            self.assertIn("error", missing_usage)
            self.assertFalse(missing_usage["usage_complete"])
            with patch("urllib.request.build_opener") as no_dispatch, self.assertRaises(ValueError):
                request({**profile, "transport": {"type": "cli_proxy"}}, {}, root / "no-dispatch.raw", 30)
            no_dispatch.assert_not_called()

    def test_cli_demo_runs_customer_acceptance_without_credentials_or_provider_calls(self):
        with tempfile.TemporaryDirectory() as temporary, patch("urllib.request.urlopen", side_effect=AssertionError("no provider traffic")):
            out = Path(temporary) / "demo"
            stream = io.StringIO()
            with patch("sys.stdout", stream):
                factory_cli(["factory-demo", "--output", str(out)])
            report = json.loads(stream.getvalue())
            self.assertEqual(report["DELIVERY_STATUS"], READY)
            self.assertTrue(report["SOURCE_UNCHANGED"])
            self.assertTrue(report["SIMULATION"])
            self.assertTrue((out / "acceptance-report.json").is_file())


if __name__ == "__main__":
    unittest.main()

"""Local-stage orchestration: real temporary Git/diffs/tests, simulated agents only."""
from __future__ import annotations

import copy
import hashlib
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, git, validate_config
from harness.factory_candidate import BILLING, LOCAL_READY
from harness.factory_cli import readable
from harness.factory_preflight import inspect_prepaid
from harness.factory_runtime import LocalRuntime
import test_factory_project as project_tests


class LocalRuntimeFixture(project_tests.ProjectRuntime):
    def __init__(self):
        super().__init__()
        self.failure = None
        self.threads = []
        self.snapshots = []

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        self.threads.append(payload.get("_thread_id"))
        result = super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
        if role in {"implement", "rework"}:
            if self.failure != "tests" and not (self.failure == "repair" and role == "implement"):
                path = cwd / "score.py"
                path.write_text(path.read_text().replace(" // ", " / "))
            if self.failure == "tests":
                path = cwd / "score.py"
                path.write_text(path.read_text().replace(" / ", " // "))
            path = cwd / "tests/test_score.py"
            path.write_text(path.read_text() +
                            "\n    def test_fractional_required(self):\n        self.assertEqual(average([1,2]), 1.5)\n")
            if self.failure == "scope":
                (cwd / "outside.txt").write_text("not authorized")
            if self.failure == "no-change":
                git(cwd, "reset", "--hard", "HEAD")
                git(cwd, "clean", "-fd")
            if self.failure in {"FAIL", "UNKNOWN"}:
                result.update(status=self.failure, error="simulated failure")
            if self.failure == "identity":
                result.pop("runtime_identity")
        # Unit fixture contract for cumulative thread usage and stable session identity.
        n = len(self.threads)
        usage = {"total": {"inputTokens": 10000 * n, "outputTokens": 1000 * n,
                            "totalTokens": 11000 * n}}
        result.update(usage=usage, thread_id="fixture-thread")
        return result


class LocalCandidateTests(unittest.TestCase):
    # Reuse the existing canonical-scope temporary repository fixture only.
    def setUp(self):
        project_tests.ProjectContractTests.setUp(self)
        self.f.close()
        self.config["budget"] = {"max_agent_runs": 5, "max_run_tokens": 30000,
                                 "max_total_tokens": 50000, "max_wall_seconds": 300}
        self.config.pop("project_contract", None)
        self.runtime = LocalRuntimeFixture()
        self.f = Factory(self.root / "state", self.config, self.runtime)
        self.addCleanup(lambda: self.f.close())
        self.spec.pop("approved_mission_scope", None)
        self.spec["scope"] = ["score.py", "tests/test_score.py"]
        self.spec.update(acceptance=["average([1,2]) == 1.5; existing add preserved"],
                         scope=self.scope["authorized_paths"], delivery_mode="local_candidate")
        self.authorize()
        self.network_patch = patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden"))
        self.network_patch.start()
        self.addCleanup(self.network_patch.stop)
        for name in ("project_review", "project_final_gate", "second_review"):
            guard = patch.object(self.runtime, name, side_effect=AssertionError("formal route forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    approval = project_tests.ProjectContractTests.approval

    def authorize(self):
        config = validate_config(self.config)
        worktree = self.f.root / "candidates/feature"
        if "project_contract" in config:
            worktree /= "source"
        authorization = {
            "approval_id": "OFFLINE-FIXTURE-ONLY", "mission_id": "feature",
            "repository": str(self.repo), "base": self.base,
            "worktree": str(worktree),
            "allowed_paths": self.spec["scope"], "acceptance": self.spec["acceptance"],
            "executor_identity": self.f.profile_identities["developer"],
            **{k: config[k] for k in ("checks", "ci", "budget", "max_rounds", "timeout_seconds", "simulation")},
            "billing": BILLING, "remote_write": "FORBIDDEN", "formal_review": "NOT_AUTHORIZED",
            "executor_permissions": "ISOLATED_CANDIDATE_ONLY_NO_NETWORK",
            "expires_at": "2099-01-01T00:00:00+00:00"}
        if "local_acceptance" in config:
            authorization["local_acceptance"] = config["local_acceptance"]
        self.spec["local_candidate_authorization"] = authorization

    def configure_project_candidate(self):
        self.f.close()
        self.config = copy.deepcopy(self.config)
        self.config.update({
            "project_contract": "footballprediction",
            "checks": [["make", "verify-targeted"]],
            "ci": [["make", "verify-pr"]],
            "trusted_validation": {
                "image": "fixture@sha256:" + "a" * 64,
                "postgres_image": "fixture-postgres@sha256:" + "b" * 64,
                "cpus": 2, "memory_mb": 4096, "pids": 256, "tmpfs_mb": 2048},
            "local_acceptance": {"profile": "targeted", "test_paths": ["tests/test_score.py"]},
        })
        self.f = Factory(self.root / "project-local-state", self.config, self.runtime)
        self.spec["scope"] = list(self.scope["authorized_paths"])
        self.spec["approved_mission_scope"] = self.approval()
        self.authorize()

    def run_candidate(self):
        self.f.submit(self.spec)
        return self.f.run("feature")

    def test_project_local_candidate_submits_materializes_and_binds_approved_scope(self):
        self.configure_project_candidate()
        with patch.object(self.runtime, "project_policy", wraps=self.runtime.project_policy) as policy:
            self.f.submit(self.spec)
            spec, cwd = self.f.prepare("feature")
            target = self.f.target(spec, cwd)

        self.assertEqual(policy.call_count, 2)
        self.assertEqual(policy.call_args_list[0].args[2], self.spec["scope"])
        self.assertEqual(policy.call_args_list[1].args[2], target["files"])
        self.assertEqual((cwd / self.path).read_bytes(), self.spec["approved_mission_scope"]["content"].encode())
        self.assertEqual(target["mission_scope_sha256"], self.spec["approved_mission_scope"]["sha256"])
        self.assertEqual(target["scope_approval_id"], self.spec["approved_mission_scope"]["approval_id"])
        self.assertEqual(target["files"], [self.path])
        self.assertEqual(git(cwd, "remote"), "")
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.runtime.final_calls, 0)
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)

    def test_project_scope_and_local_authority_mismatches_reject_before_dispatch(self):
        self.configure_project_candidate()
        original = copy.deepcopy(self.spec)
        wrong_content = json.loads(original["approved_mission_scope"]["content"])
        wrong_content["authorized_paths"].remove("tests/test_score.py")
        wrong_content = json.dumps(wrong_content, ensure_ascii=False, indent=2) + "\n"
        cases = {
            "mission": lambda spec: spec["approved_mission_scope"].update(mission_id="other"),
            "base": lambda spec: spec["approved_mission_scope"].update(base="0" * 40),
            "project_paths": lambda spec: spec["approved_mission_scope"].update(
                content=wrong_content, sha256=hashlib.sha256(wrong_content.encode()).hexdigest()),
            "repository": lambda spec: spec["local_candidate_authorization"].update(repository="/tmp/other"),
            "candidate_paths": lambda spec: spec["local_candidate_authorization"].update(allowed_paths=["**"]),
            "missing_scope": lambda spec: spec.pop("approved_mission_scope"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                self.spec = copy.deepcopy(original)
                mutate(self.spec)
                with self.assertRaises(ValueError):
                    self.f.submit(self.spec)
                self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM missions").fetchone()[0], 0)
                self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
                self.assertEqual(self.runtime.calls, [])

    def test_project_scope_approval_is_rejected_without_project_contract(self):
        self.spec["approved_mission_scope"] = self.approval()
        self.authorize()
        with self.assertRaisesRegex(ValueError, "explicit project_contract mode"):
            self.f.submit(self.spec)
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM missions").fetchone()[0], 0)
        self.assertEqual(self.runtime.calls, [])

    def test_project_contract_requires_its_scope_approval_and_rejects_unknown_contract(self):
        self.configure_project_candidate()
        self.spec.pop("approved_mission_scope")
        self.authorize()
        with self.assertRaisesRegex(ValueError, "approved_mission_scope is required"):
            self.f.submit(self.spec)
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM missions").fetchone()[0], 0)
        self.assertEqual(self.runtime.calls, [])

        invalid = copy.deepcopy(self.config)
        invalid["project_contract"] = "footballprediction-unknown"
        with self.assertRaisesRegex(ValueError, "project mode is explicit"):
            validate_config(invalid)

    def ready(self):
        report = self.run_candidate()
        self.assertEqual(report["DELIVERY_STATUS"], LOCAL_READY, report)
        return report

    def test_cumulative_usage_increments_and_unsafe_snapshots_fail_closed(self):
        from harness.factory_candidate import usage_increment
        first = {"total": {"inputTokens": 18000, "outputTokens": 2000, "totalTokens": 20000,
                            "cachedInputTokens": 4000, "reasoningOutputTokens": 500}}
        second = {"total": {"inputTokens": 30000, "outputTokens": 5000, "totalTokens": 35000,
                             "cachedInputTokens": 7000, "reasoningOutputTokens": 1200}}
        one = usage_increment(first, None)
        two = usage_increment(second, one[1])
        self.assertEqual(one[0]["totalTokens"], 20000)
        self.assertEqual(two[0]["totalTokens"], 15000)
        self.assertEqual(usage_increment({"total": {"inputTokens": 1, "outputTokens": 1,
            "totalTokens": 2}}, one[1]), None)
        self.assertEqual(usage_increment(None, one[1]), None)

    def test_localruntime_reuses_one_appserver_process_and_thread_for_repair_turn(self):
        class FakeServer:
            instances = []
            def __init__(self, profile, cwd, transcript, timeout, denied, readonly, reviewer, token_limit,
                         protected_paths=()):
                self.transcript = transcript
                self._transcript_bytes = 0
                self.proc = object()
                self._proxy_relay = None
                self.runtime_identity = {"provider": "openai", "model": "fixture", "thread_id": "thread-1"}
                self.closed = 0
                self.turn = 0
                self.__class__.instances.append(self)
            def execute(self, prompt, schema, thread_id=None, return_thread=False):
                self.turn += 1
                return {"output": {"summary": "done", "known_risks": []},
                        "usage": {"total": {"inputTokens": self.turn * 20,
                            "outputTokens": self.turn * 5, "totalTokens": self.turn * 25}},
                        "thread_id": thread_id or "thread-1" if return_thread else None}
            def close(self):
                self.closed += 1
        with tempfile.TemporaryDirectory() as directory, patch("harness.factory_runtime.FactoryAppServer", FakeServer):
            root = Path(directory)
            runtime = LocalRuntime()
            profile = {"provider": "openai", "model": "fixture"}
            denied = [root / "state", root / "source"]
            first = runtime.agent("implement", profile, root, {"_return_thread": True, "_reuse_session": True},
                                  root / "first.raw", 30, denied)
            second = runtime.agent("rework", profile, root, {"_thread_id": first["thread_id"],
                                   "_return_thread": True, "_reuse_session": True},
                                   root / "second.raw", 30, denied)
            self.assertEqual(first["thread_id"], second["thread_id"])
            self.assertEqual(len(FakeServer.instances), 1)
            self.assertEqual(FakeServer.instances[0].turn, 2)
            runtime.close_session()
            self.assertEqual(FakeServer.instances[0].closed, 1)

    def test_authorized_summary_resolves_pending_draft_but_real_scope_conflict_blocks(self):
        self.spec.setdefault("constraints", []).append("Model execution is pending approval before implementation")
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.f.submit(self.spec)
        self.assertEqual(self.runtime.calls, [])

    def test_targeted_python_acceptance_requires_changed_source_tests_and_real_log(self):
        from harness.factory_candidate import acceptance, validate_policy
        config = {"project_contract": "footballprediction", "trusted_validation": {"version": 1},
                  "checks": [["make", "verify-targeted"]],
                  "local_acceptance": {"profile": "targeted", "test_paths": ["tests/unit/test_x.py"]}}
        validate_policy(config)
        spec = {"delivery_mode": "local_candidate", "mission_scope_file": "scope.json"}
        target = {"files": ["src/x.py", "tests/unit/test_x.py", "scope.json"]}
        text = ("[Validation] profile=targeted changed_files=2\n"
                "[Validation] Python changed-line static check: passed\n"
                "[Validation] Python format check: passed\n"
                "[Validation] changed Python tests: /usr/local/bin/python3 -m pytest -q tests/unit/test_x.py\n"
                "2 passed in 0.1s\n")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "validation.log"
            log.write_text(text)
            result = {"status": "PASS", "exit_code": 0, "log_path": str(log),
                      "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "evidence_key": "qa"}
            self.assertEqual(acceptance(spec, config, target, [result])["status"], "PASS")
            result["log_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                acceptance(spec, config, target, [result])

    def test_explicit_complete_authorization_required_before_prepare_or_dispatch(self):
        original = copy.deepcopy(self.spec)
        for key in original["local_candidate_authorization"]:
            self.spec = copy.deepcopy(original)
            del self.spec["local_candidate_authorization"][key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.f.submit(self.spec)
        self.spec = {k: v for k, v in original.items() if k != "delivery_mode"}
        with self.assertRaises(ValueError):
            self.f.submit(self.spec)
        self.assertFalse((self.f.root / "candidates").exists())
        self.assertEqual(self.runtime.calls, [])

    def test_wrong_authority_identity_scope_budget_and_permissions_rejected(self):
        original = copy.deepcopy(self.spec)
        mutations = {"worktree": "/tmp/another-checkout", "executor_identity": {"other": True},
                     "base": "0" * 40, "allowed_paths": ["**"], "budget": {"max_agent_runs": 99},
                     "checks": [["true"]], "formal_review": "AUTHORIZED", "remote_write": "ALLOWED",
                     "expires_at": "2000-01-01T00:00:00Z", "simulation": False}
        for key, value in mutations.items():
            self.spec = copy.deepcopy(original)
            self.spec["local_candidate_authorization"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.f.submit(self.spec)
        self.assertEqual(self.runtime.calls, [])

    def test_real_orchestration_diff_exit_logs_and_complete_candidate_evidence(self):
        before = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob("*") if p.is_file()}
        report = self.ready()
        evidence = report["LOCAL_CANDIDATE_EVIDENCE"]
        self.assertIn("def average", Path(evidence["patch"]["path"]).read_text())
        self.assertIn("score.py", evidence["target"]["files"])
        self.assertEqual(evidence["target"]["base"], self.base)
        for kind in ("checks", "ci"):
            for result in evidence["validation_results"][kind]:
                self.assertEqual(result["exit_code"], 0)
                self.assertTrue(Path(result["raw_evidence"][0]["path"]).is_file())
        self.assertEqual(evidence["execution_status"], "SIMULATED_EXECUTION_COMPLETE")
        self.assertTrue(report["SIMULATION"])
        self.assertFalse(report["READY_FOR_MERGE"])
        self.assertEqual(report["DUAL_RECEIPT"], "PENDING")
        self.assertEqual(report["REMOTE_WRITE_STATUS"], "NOT_EXECUTED")
        self.assertEqual(self.runtime.final_calls, 0)
        self.assertEqual(report["OBSERVED_TOKEN_USAGE"]["total"], 11000)
        self.assertEqual([r[0] for r in self.f.db.execute("SELECT stage FROM operations ORDER BY started")],
                         ["implement", "checks", "ci"])
        self.assertEqual(before, {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob("*") if p.is_file()})
        self.assertEqual(git(Path(report["CANDIDATE"]), "remote"), "")
        self.assertIn("LOCAL_CANDIDATE_READY", readable(report))

    def test_real_test_failure_automatically_repaired_without_review(self):
        self.runtime.failure = "repair"
        report = self.ready()
        self.assertEqual(report["LOCAL_CANDIDATE_EVIDENCE"]["repair_attempts"], 1)
        self.assertIn("rework", [c["role"] for c in self.runtime.calls])
        self.assertEqual(self.runtime.threads, [None, "fixture-thread"])
        self.assertEqual(report["OBSERVED_TOKEN_USAGE"]["total"], 22000)
        failed = self.f.db.execute("SELECT result FROM operations WHERE stage='checks' ORDER BY started LIMIT 1").fetchone()
        self.assertNotEqual(json.loads(failed[0])["exit_code"], 0)

    def test_persistent_test_failure_exhausts_bounded_repair_without_success(self):
        self.runtime.failure = "tests"
        report = self.run_candidate()
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_LIMIT", report)
        self.assertFalse(report["LOCAL_CANDIDATE_READY"])
        self.assertEqual(len([c for c in self.runtime.calls if c["role"] == "rework"]), 1)

    def test_failed_executor_never_candidate(self):
        self.runtime.failure = "FAIL"
        self.assertEqual(self.run_candidate()["DELIVERY_STATUS"], "UNKNOWN")

    def test_unknown_executor_never_replayed(self):
        self.runtime.failure = "UNKNOWN"
        self.assertEqual(self.run_candidate()["DELIVERY_STATUS"], "UNKNOWN")
        calls = len(self.runtime.calls)
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(calls, len(self.runtime.calls))

    def test_missing_executor_identity_never_candidate(self):
        self.runtime.failure = "identity"
        self.assertEqual(self.run_candidate()["DELIVERY_STATUS"], "UNKNOWN")

    def test_no_actual_change_never_candidate(self):
        self.runtime.failure = "no-change"
        self.assertEqual(self.run_candidate()["DELIVERY_STATUS"], "UNKNOWN")

    def test_out_of_scope_change_rejected(self):
        self.runtime.failure = "scope"
        self.assertEqual(self.run_candidate()["DELIVERY_STATUS"], "BLOCKED_SCOPE")

    def test_run_budget_blocks_before_implementation(self):
        self.f.close()
        self.config["budget"]["max_agent_runs"] = 1
        self.f = Factory(self.root / "state", self.config, self.runtime)
        self.authorize()
        with self.assertRaisesRegex(ValueError, "permit initial execution"):
            self.f.submit(self.spec)
        self.assertEqual(len(self.runtime.calls), 0)

    def test_token_budget_blocks_before_implementation(self):
        self.f.close()
        self.config["budget"]["max_total_tokens"] = 10000
        self.config["budget"]["max_run_tokens"] = 6000
        self.f = Factory(self.root / "state", self.config, self.runtime)
        self.authorize()
        original = self.runtime.agent
        def with_tokens(*args, **kwargs):
            result = original(*args, **kwargs)
            result["usage"] = {"total": {"inputTokens": 6000, "outputTokens": 1000, "totalTokens": 7000}}
            return result
        with patch.object(self.runtime, "agent", side_effect=with_tokens):
            report = self.run_candidate()
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET", report)

    def test_completed_candidate_is_durable_stop_and_cannot_authorize_formal_actions(self):
        report = self.ready()
        count = self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        self.f.close()
        self.runtime = LocalRuntimeFixture()
        self.f = Factory(self.root / "state", self.config, self.runtime)
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], LOCAL_READY)
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(count, self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0])
        with self.assertRaises(ValueError):
            self.f.approve("feature", "merge", "not formal", report["TARGET_HEAD"])
        with self.assertRaises((FactoryBlocked, ValueError)):
            self.f.approve_pr_publication("feature", report["TARGET_HEAD"], "not authorized", "body")
        with self.assertRaises(FactoryBlocked):
            self.f.operation("feature", "forbidden", "review", "reviewer", {}, {}, True,
                             lambda _: self.fail("no dispatch"))

    def test_tampered_patch_or_logs_fail_revalidation_without_resume_calls(self):
        report = self.ready()
        path = Path(report["LOCAL_CANDIDATE_EVIDENCE"]["patch"]["path"])
        path.chmod(0o600)
        path.write_text("changed")
        calls = len(self.runtime.calls)
        self.assertEqual(self.f.report("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(calls, len(self.runtime.calls))

    def test_missing_test_log_cannot_form_candidate(self):
        original = self.runtime.gate
        def missing_log(*args):
            result = original(*args)
            args[3].unlink()
            return result
        with patch.object(self.runtime, "gate", side_effect=missing_log):
            report = self.run_candidate()
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
        self.assertFalse(report["LOCAL_CANDIDATE_READY"])

    def test_unknown_or_skipped_test_never_candidate(self):
        with patch.object(self.runtime, "gate", return_value={"status": "SKIPPED", "exit_code": 0}):
            self.assertEqual(self.run_candidate()["DELIVERY_STATUS"], "UNKNOWN")

    def test_candidate_head_change_remains_stopped(self):
        report = self.ready()
        cwd = Path(report["CANDIDATE"])
        (cwd / "score.py").write_text("changed after verification")
        calls = len(self.runtime.calls)
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(calls, len(self.runtime.calls))

    def test_wall_authority_exhaustion_stops_before_dispatch(self):
        self.f.submit(self.spec)
        # Immutable events are preserved; advance the observed clock instead.
        import time
        with patch("harness.factory.time.time", return_value=time.time() + 301):
            report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_BUDGET", report)
        self.assertEqual(self.runtime.calls, [])

    def test_local_preflight_does_not_require_unexecuted_deepseek_but_keeps_runtime_checks(self):
        config = validate_config({**self.config, "simulation": False})
        self.spec["local_candidate_authorization"]["simulation"] = False
        with patch("harness.factory_preflight.shutil.which", return_value=None):
            result = inspect_prepaid(self.spec, config)
        blockers = [f["check"] for f in result["findings"] if f["level"] == "HARD_BLOCKER"]
        self.assertNotIn("first_paid_execution", blockers)
        self.assertIn("local_runtime", blockers)
        formal = {k: v for k, v in self.spec.items() if k not in {"delivery_mode", "local_candidate_authorization"}}
        formal_config = {**config, "project_contract": "footballprediction"}
        blockers = [f["check"] for f in inspect_prepaid(formal, formal_config)["findings"] if f["level"] == "HARD_BLOCKER"]
        self.assertIn("first_paid_execution", blockers)

    def test_shared_wallet_or_remote_configuration_not_implicitly_authorized(self):
        for name in ("task_budget", "project_pr_ci", "hosted_ci"):
            with self.subTest(name=name):
                self.f.config[name] = {}
                with self.assertRaises(ValueError):
                    self.f.submit(self.spec)
                del self.f.config[name]


if __name__ == "__main__":
    unittest.main()

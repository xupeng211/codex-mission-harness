"""Local targeted delivery: real temporary Git/business tests, no model or Docker.

Docker transport and project policy are explicit doubles. This does not qualify
the real FootballPrediction image, static checks, reviewers, or provider lanes.
"""
from __future__ import annotations

import copy
import hashlib
import shlex
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, digest, git, policy_identity
from harness.factory_candidate import BILLING, LOCAL_READY, STRICT_DIRECT_MARKER, acceptance, validate_policy
from harness.factory_progress import ProgressGuard, check_dispatch
from harness.factory_runtime import LocalRuntime
from harness.factory_validation import DockerExecutor, preflight
from test_factory_candidate import LocalRuntimeFixture
from test_factory_phase2 import FakeDocker, VALIDATION, LOCKS, QA_SOURCE
import test_factory_project as project_tests


class BusinessDocker(FakeDocker):
    def __init__(self):
        super().__init__()
        self.on_capture = lambda: None
        self.captures = []
        self.strict_failures = 0

    def capture(self, container, path, timeout, cancelled, **control):
        self.captures.append(control)
        self.on_capture()
        if self.failure == "silent":
            Path(path).write_text("fixture partial output\n")
            raise TimeoutError("fixture silent validation")
        if cancelled():
            raise InterruptedError("fixture validation cancelled")
        created = self.containers[container]
        snapshot = Path(re.search(r"src=([^,]+)", created[created.index("--mount") + 1])[1])
        # Exercise the generated shell's status propagation and strict-before-
        # targeted ordering. The dispatcher is an explicit offline double; its
        # targeted branch runs real pytest on the frozen temporary business repo.
        dispatcher = r"""
import subprocess, sys
profile = sys.argv[1]
print('[Validation] profile=' + profile + ' changed_files=2', flush=True)
if profile == 'strict':
    print('[Validation] full Production Gate implementation: bash scripts/devops/gatekeeper.sh --mode=push', flush=True)
    if sys.argv[2] == 'fail':
        print('fixture strict gate failed', flush=True)
        sys.exit(1)
    print('[Gatekeeper] 门禁通过（mode=push）。', flush=True)
else:
    print('[Validation] Python changed-line static check: fixture', flush=True)
    print('[Validation] Python format check: fixture', flush=True)
    print('[Validation] changed Python tests: /usr/local/bin/python3 -m pytest -q tests/test_score.py', flush=True)
    sys.exit(subprocess.call([sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/test_score.py']))
"""
        script = created[-1]
        script = 'status=0; ' + script.split('; status=0; ', 1)[1].split('after=$(git status', 1)[0] + 'exit "$status"'
        strict = 'validation_profiles.py strict' in script
        fail = strict and self.strict_failures > 0
        if fail:
            self.strict_failures -= 1
        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / 'fixture_dispatcher.py'
            stub.write_text(dispatcher)
            script = re.sub(r'/usr/local/bin/python3 -I /(?:snapshot|app)/scripts/devops/validation_profiles.py (strict|targeted)',
                            lambda m: shlex.quote(sys.executable) + ' ' + shlex.quote(str(stub)) + ' ' + m[1] + (' fail' if fail else ' pass'), script)
            result = subprocess.run(['/bin/sh', '-ec', script], cwd=snapshot, capture_output=True, timeout=10,
                                    env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                                         "PYTHONPATH": str(snapshot / "src"), "PYTHONDONTWRITEBYTECODE": "1",
                                         "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
        self.exit_code = result.returncode
        Path(path).write_bytes(self.call("logs", container) + result.stdout + result.stderr)
        return result.returncode


class TargetedRuntime(LocalRuntimeFixture):
    def __init__(self):
        super().__init__()
        self.resource_policy = {}
        self._validation_cancelled = False
        self.docker = BusinessDocker()
        self.tool_events = []

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        result = super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
        (cwd / "src/score.py").write_bytes((cwd / "score.py").read_bytes())
        (cwd / "score.py").unlink()
        if payload.get("_progress_scope"):
            guard = ProgressGuard(cwd, payload["_progress_scope"], self.tool_events.append)
            # Several necessary reads within one turn; real native protocol
            # dispatch is separately covered by test_factory_progress.
            for name in ("src/score.py", "tests/test_score.py", "src/score.py"):
                event = {"method": "item/completed", "params": {"item": {
                    "type": "commandExecution", "command": "cat " + name,
                    "commandActions": [{"type": "read"}], "exitCode": 0,
                    "aggregatedOutput": (cwd / name).read_text()}}}
                guard.observe(event)
                self.tool_events.append(event)
        return result

    def project_validation(self, *args):
        with patch("harness.factory_validation.DockerExecutor", return_value=self.docker):
            return LocalRuntime.project_validation(self, *args)


class ProgressLocalTests(unittest.TestCase):
    approval = project_tests.ProjectContractTests.approval

    def setUp(self):
        project_tests.ProjectContractTests.setUp(self)
        self.f.close()
        (self.repo / "src").mkdir()
        (self.repo / "score.py").rename(self.repo / "src/score.py")
        for name, value in {**LOCKS, **QA_SOURCE}.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "local QA fixture")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.scope.update(workflow_class="NORMAL", authorized_paths=["src/score.py", "tests/test_score.py", self.path])
        self.spec.update(base=self.base, acceptance=["average([1,2]) == 1.5; add preserved"],
                         scope=self.scope["authorized_paths"], delivery_mode="local_candidate",
                         approved_mission_scope=self.approval())
        self.config.update(budget={}, execution_policy={"mode": "progress_driven", "idle_timeout_seconds": 1},
                           checks=[["make", "verify-targeted"]], ci=[["make", "verify-pr"]],
                           trusted_validation=copy.deepcopy(VALIDATION),
                           local_acceptance={"profile": "targeted", "test_paths": ["tests/test_score.py"]})
        self.config.pop("max_rounds")
        self.runtime = TargetedRuntime()
        self.runtime.usage_totals = [150001, 300002]
        self.f = Factory(self.root / "progress-local-state", self.config, self.runtime)
        self.addCleanup(lambda: self.f.close())
        self.authorize()
        def probe(policy, executor=None, *args, **kwargs):
            result = preflight(policy, executor or self.runtime.docker, *args, **kwargs)
            if executor is None:
                # Simulate the live readiness boundary only for this fixture.
                # Never change production preflight or treat this as real QA.
                result.update(status="VERIFIED", fixture=True)
            return result
        probe_patch = patch("harness.factory_validation.preflight", side_effect=probe)
        probe_patch.start()
        self.addCleanup(probe_patch.stop)
        network = patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)
        for name in ("project_review", "project_final_gate", "second_review"):
            guard = patch.object(self.runtime, name, side_effect=AssertionError("formal path must not run"))
            guard.start()
            self.addCleanup(guard.stop)

    def authorize(self):
        worktree = str(self.f.root / "candidates/feature/source")
        self.spec["progress_authorization"] = {
            "approval_id": "OFFLINE-ONLY", **{k: self.spec[k] for k in ("mission_id", "repository", "base", "objective", "acceptance")},
            "allowed_paths": self.spec["scope"], "worktree": worktree,
            "policy_sha256": digest(policy_identity(self.f.config)), "lane_identities": self.f.profile_identities,
            "financial": {k: "prepaid_only" for k in self.f.profile_identities},
            "expires_at": "2099-01-01T00:00:00+00:00"}
        # Project reviewers have canonical identities, separate from this
        # Developer-only profile map. No paid review is authorized by omission.
        self.spec["local_candidate_authorization"] = {
            "approval_id": "OFFLINE-LOCAL", **{k: self.spec[k] for k in ("mission_id", "repository", "base", "acceptance")},
            "allowed_paths": self.spec["scope"], "worktree": worktree,
            "executor_identity": self.f.profile_identities["developer"],
            **{k: self.f.config[k] for k in ("checks", "ci", "budget", "timeout_seconds", "simulation", "execution_policy", "local_acceptance")},
            "billing": BILLING, "remote_write": "FORBIDDEN", "formal_review": "NOT_AUTHORIZED",
            "executor_permissions": "ISOLATED_CANDIDATE_ONLY_NO_NETWORK", "expires_at": "2099-01-01T00:00:00+00:00"}

    def run_local(self):
        self.f.submit(self.spec)
        return self.f.run("feature")

    def test_targeted_checkpoint_and_business_qa_after_old_token_and_time_thresholds(self):
        clock = [time.monotonic()]
        self.runtime.docker.on_capture = lambda: clock.__setitem__(0, clock[0] + 100000)
        clock_api = SimpleNamespace(monotonic=lambda: clock[0], time=time.time, sleep=time.sleep)
        with patch("harness.factory_validation.time", clock_api):
            report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], LOCAL_READY, report)
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 150001)
        self.assertEqual(self.runtime.operation_limits, [("implement", None)])
        self.assertEqual(len(self.runtime.tool_events), 3)
        checks = report["TRUSTED_QA_RESULT"]["checks"]
        self.assertEqual(len(checks), 1)
        result = checks[0]
        self.assertEqual(result["execution_control"]["mode"], "progress_driven")
        self.assertEqual(self.runtime.docker.captures, [{"idle_timeout": 1}])
        self.assertEqual(result["identity"]["head"], report["FINAL_HEAD_SHA"])
        self.assertNotEqual(report["FINAL_HEAD_SHA"], self.base)
        cwd = Path(report["CANDIDATE"])
        self.assertEqual(git(cwd, "status", "--porcelain"), "")
        self.assertIn("src/score.py", git(cwd, "show", "--format=", "--name-only", "HEAD"))
        self.assertIn("passed", Path(result["log_path"]).read_text())
        self.assertEqual(report["LOCAL_ACCEPTANCE"]["status"], "PASS")
        for key in ("FORMAL_REVIEW", "CI_RESULT", "HOSTED_CI"):
            self.assertEqual(report[key], "NOT_EXECUTED")
        self.assertFalse(report["READY_FOR_MERGE"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_failed_business_test_repairs_same_thread_then_recheckpoints(self):
        self.runtime.failure = "repair"
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], LOCAL_READY, report)
        self.assertEqual(self.runtime.threads, [None, "fixture-thread"])
        self.assertEqual(self.runtime.operation_limits, [("implement", None), ("rework", None)])
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 300002)
        rows = self.f.db.execute("SELECT result FROM operations WHERE stage='checks' ORDER BY started").fetchall()
        results = [json.loads(row[0]) for row in rows]
        self.assertEqual([r["status"] for r in results], ["FAIL", "PASS"])
        self.assertNotEqual(results[0]["identity"]["head"], results[1]["identity"]["head"])
        self.assertIn("AssertionError", Path(results[0]["log_path"]).read_text())
        self.assertEqual(report["FORMAL_REVIEW"], "NOT_EXECUTED")

    def test_unknown_validation_retained_without_automatic_repair_or_replay(self):
        self.runtime.docker.failure = "silent"
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
        self.assertEqual(self.runtime.threads, [None])
        rows = [tuple(row) for row in self.f.db.execute("SELECT id,status,result FROM operations ORDER BY started")]
        self.assertEqual(rows[-1][1], "UNKNOWN")
        self.runtime.docker.failure = None
        self.f.run("feature")
        self.assertEqual(rows, [tuple(row) for row in self.f.db.execute("SELECT id,status,result FROM operations ORDER BY started")])
        self.assertEqual(len(self.runtime.docker.captures), 1)

    def test_strict_scope_cannot_downgrade_required_profile_to_targeted(self):
        self.scope["workflow_class"] = "STRICT"
        self.spec["approved_mission_scope"] = self.approval()
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_PROJECT_CONTRACT", report)
        self.assertEqual(self.runtime.docker.captures, [])

    def test_missing_project_reviewer_lanes_never_grant_paid_authority(self):
        self.f.close()
        config = copy.deepcopy(self.config)
        config["simulation"] = False
        config["profiles"]["developer"]["codex_home"] = str(self.root / "absent-auth")
        class LiveDouble(TargetedRuntime):
            simulation = False
        self.f = Factory(self.root / "live-admission-only", config, LiveDouble())
        self.authorize()
        self.f.submit(self.spec)
        self.assertEqual(set(self.spec["progress_authorization"]["financial"]), {"developer"})
        for lane in ("developer", "reviewer", "second_reviewer"):
            # Use a non-canonical stage to test the financial guard itself,
            # independent of the canonical-review compatibility rejection.
            with self.assertRaises(FactoryBlocked) as stopped:
                check_dispatch(self.f, "feature", "implement", lane, True)
            self.assertEqual(stopped.exception.status, "BLOCKED_FINANCIAL")
        self.assertFalse(self.f.runtime.calls)

    def test_attachment_completion_without_container_exit_stops_unknown(self):
        clock = [time.monotonic()]
        def mutate(value):
            if self.runtime.docker.captures:
                value["State"]["Status"] = "running"
        self.runtime.docker.mutate = mutate
        clock_api = SimpleNamespace(monotonic=lambda: clock[0], time=time.time,
                                    sleep=lambda _: clock.__setitem__(0, clock[0] + 31))
        with patch("harness.factory_validation.time", clock_api):
            report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
        row = self.f.db.execute("SELECT result FROM operations WHERE stage='checks'").fetchone()
        result = json.loads(row[0])
        self.assertIn("terminal state", result["error"])
        self.assertTrue(result["interrupted"])
        self.assertEqual(result["cleanup"], "COMPLETE")
        self.assertTrue(any(c[0] == "kill" for c in self.runtime.docker.calls))


class StrictLocalTests(unittest.TestCase):
    approval = ProgressLocalTests.approval
    authorize = ProgressLocalTests.authorize
    run_local = ProgressLocalTests.run_local

    def setUp(self):
        ProgressLocalTests.setUp(self)
        self.f.close()
        self.scope["workflow_class"] = "STRICT"
        self.spec["approved_mission_scope"] = self.approval()
        self.config.update(checks=[["make", "verify-strict"]],
                           local_acceptance={"profile": "strict", "test_paths": ["tests/test_score.py"]})
        self.f = Factory(self.root / "strict-local-state", self.config, self.runtime)
        self.authorize()

    def test_developer_checkpoint_full_strict_then_direct_tests_no_formal_claim(self):
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], LOCAL_READY, report)
        result = report["TRUSTED_QA_RESULT"]["checks"][0]
        log = Path(result["log_path"]).read_text()
        self.assertLess(log.index("profile=strict"), log.index(STRICT_DIRECT_MARKER))
        self.assertLess(log.index("门禁通过"), log.index("profile=targeted"))
        self.assertIn("passed", log)
        self.assertEqual(result["identity"]["profile"], "strict")
        self.assertEqual(report["LOCAL_ACCEPTANCE"]["mode"], "strict")
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 150001)
        self.assertEqual(self.runtime.operation_limits, [("implement", None)])
        self.assertEqual(report["EXACT_TARGET"]["project_policy"]["workflow_class"], "STRICT")
        self.assertNotEqual(report["FINAL_HEAD_SHA"], self.base)
        self.assertEqual(git(Path(report["CANDIDATE"]), "status", "--porcelain"), "")
        self.assertEqual([r[0] for r in self.f.db.execute("SELECT stage FROM operations ORDER BY started")], ["implement", "checks"])
        for key in ("FORMAL_REVIEW", "CI_RESULT", "LOCAL_CI", "HOSTED_CI", "REMOTE_WRITE_STATUS"):
            self.assertEqual(report[key], "NOT_EXECUTED")
        self.assertFalse(report["READY_FOR_MERGE"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_strict_gate_failure_skips_supplement_then_same_thread_repair(self):
        self.runtime.docker.strict_failures = 1
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], LOCAL_READY, report)
        results = [json.loads(r[0]) for r in self.f.db.execute("SELECT result FROM operations WHERE stage='checks' ORDER BY started")]
        self.assertEqual([r["status"] for r in results], ["FAIL", "PASS"])
        self.assertNotIn(STRICT_DIRECT_MARKER, Path(results[0]["log_path"]).read_text())
        self.assertIn("fixture strict gate failed", Path(results[0]["log_path"]).read_text())
        self.assertNotEqual(results[0]["identity"]["head"], results[1]["identity"]["head"])
        self.assertEqual(self.runtime.threads, [None, "fixture-thread"])
        self.assertEqual(report["FORMAL_REVIEW"], "NOT_EXECUTED")

    def test_direct_business_test_failure_requires_repair_and_full_strict_rerun(self):
        self.runtime.failure = "repair"
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], LOCAL_READY, report)
        results = [json.loads(r[0]) for r in self.f.db.execute("SELECT result FROM operations WHERE stage='checks' ORDER BY started")]
        self.assertEqual([r["status"] for r in results], ["FAIL", "PASS"])
        for result in results:
            log = Path(result["log_path"]).read_text()
            self.assertIn("profile=strict", log)
            self.assertIn(STRICT_DIRECT_MARKER, log)
        self.assertIn("AssertionError", Path(results[0]["log_path"]).read_text())
        self.assertEqual(self.runtime.threads, [None, "fixture-thread"])

    def test_matching_profile_and_immutable_authorization_required(self):
        config = copy.deepcopy(self.config)
        config["checks"] = [["make", "verify-targeted"]]
        with self.assertRaises(ValueError):
            validate_policy(config)
        self.spec["local_candidate_authorization"]["local_acceptance"] = {"profile": "targeted", "test_paths": ["tests/test_score.py"]}
        with self.assertRaisesRegex(ValueError, "differs"):
            self.f.submit(self.spec)
        self.assertFalse(self.runtime.calls)

    def test_missing_or_failed_strict_or_direct_evidence_never_passes(self):
        report = self.run_local()
        result = report["TRUSTED_QA_RESULT"]["checks"][0]
        text = Path(result["log_path"]).read_text()
        bound_spec = json.loads(self.f.row("feature")["spec"])
        cases = [text.replace("[Gatekeeper] 门禁通过（mode=push）。", ""),
                 text.replace("profile=strict", "profile=targeted"),
                 text.replace(STRICT_DIRECT_MARKER, "absent"),
                 text.split(STRICT_DIRECT_MARKER)[0],
                 text + "1 skipped\n"]
        for number, value in enumerate(cases):
            path = self.root / ("tampered-" + str(number))
            path.write_text(value)
            tampered = {**result, "log_path": str(path), "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            with self.subTest(number=number), self.assertRaises(ValueError):
                acceptance(bound_spec, self.f.config, report["EXACT_TARGET"], [tampered])
        # Canonical strict may have its own permitted skips; the supplemental
        # direct test still must actually execute without skips/deselection.
        path = self.root / "canonical-skip"
        path.write_text(text.replace(STRICT_DIRECT_MARKER, "1 skipped\n" + STRICT_DIRECT_MARKER))
        accepted = {**result, "log_path": str(path), "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        self.assertEqual(acceptance(bound_spec, self.f.config, report["EXACT_TARGET"], [accepted])["mode"], "strict")

    def test_strict_unknown_retained_without_replay(self):
        ProgressLocalTests.test_unknown_validation_retained_without_automatic_repair_or_replay(self)

    def test_legacy_budget_local_strict_keeps_limits_and_acceptance(self):
        import test_factory_candidate as legacy
        self.f.close()
        self.config.pop("execution_policy")
        self.config.update(max_rounds=2, budget={"max_agent_runs": 5, "max_run_tokens": 36000,
                           "max_first_turn_tokens": 60000, "max_repair_incremental_tokens": 36000,
                           "max_total_tokens": 96000, "max_wall_seconds": 300})
        self.runtime.usage_totals = [11000, 22000]
        self.f = Factory(self.root / "legacy-strict-local", self.config, self.runtime)
        self.spec.pop("progress_authorization")
        legacy.LocalCandidateTests.authorize(self)
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], LOCAL_READY, report)
        self.assertEqual(report["LOCAL_ACCEPTANCE"]["mode"], "strict")
        self.assertEqual(self.runtime.operation_limits, [("implement", 60000)])
        result = report["TRUSTED_QA_RESULT"]["checks"][0]
        self.assertNotIn("execution_control", result)
        self.assertEqual(self.runtime.docker.captures, [{}])

    def test_source_with_base_only_on_remote_tracking_ref_stops_before_developer(self):
        # Reproduce the real startup cause without touching a project repository.
        tree = git(self.repo, "rev-parse", self.base + "^{tree}")
        self.base = git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost",
                        "commit-tree", tree, "-m", "unadvertised exact baseline")
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.base)
        self.spec["base"] = self.base
        self.spec["approved_mission_scope"] = self.approval()
        self.authorize()
        report = self.run_local()
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
        self.assertFalse(self.runtime.calls)
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertFalse(self.runtime.calls)

    def test_candidate_object_isolation_failure_stops_before_developer(self):
        self.f.submit(self.spec)
        _, cwd = self.f.prepare("feature")
        (cwd / ".git/objects/info/alternates").write_text(str(self.repo / ".git/objects") + "\n")
        report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
        self.assertFalse(self.runtime.calls)
        self.assertEqual(self.runtime.docker.captures, [])

    def test_ci_review_and_remote_dispatch_remain_forbidden(self):
        from harness.factory_candidate import check_dispatch as local_dispatch
        self.f.submit(self.spec)
        for stage in ("ci", "review", "second_review", "push", "merge", "deploy"):
            with self.subTest(stage=stage), self.assertRaises(FactoryBlocked) as stopped:
                local_dispatch(self.f, "feature", stage)
            self.assertEqual(stopped.exception.status, "BLOCKED_LOCAL_AUTHORITY")
        self.assertFalse(self.runtime.calls)


class CaptureTests(unittest.TestCase):
    def capture(self, code, *, progress=True, cancelled=lambda: False):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "capture.raw"
        original = subprocess.Popen
        self.proc = None
        def launch(*args, **kwargs):
            self.proc = original([sys.executable, "-u", "-c", code], **kwargs)
            return self.proc
        with patch("harness.factory_validation.subprocess.Popen", side_effect=launch):
            return DockerExecutor().capture("fixture-no-docker", self.log, 1, cancelled,
                                            **({"idle_timeout": 1} if progress else {}))

    def test_output_progress_outlives_total_timeout(self):
        self.assertEqual(self.capture("import time; [(print(n,flush=True),time.sleep(.2)) for n in range(9)]"), 0)
        activity = json.loads(self.log.with_suffix(".activity.json").read_text())
        self.assertGreater(activity["output_updates"], 1)
        self.assertIsNone(activity["stop_reason"])

    def test_strict_capture_still_uses_absolute_deadline_despite_output(self):
        with self.assertRaisesRegex(TimeoutError, "execution timed out"):
            self.capture("import time; [(print(n,flush=True),time.sleep(.2)) for n in range(100)]", progress=False)
        self.assertIsNotNone(self.proc.poll())
        self.assertFalse(self.log.with_suffix(".activity.json").exists())

    def test_silent_process_stops_and_keeps_partial_log_and_diagnosis(self):
        with self.assertRaisesRegex(TimeoutError, "silent"):
            self.capture("import time; print('started',flush=True); time.sleep(60)")
        self.assertIsNotNone(self.proc.poll())
        self.assertIn("started", self.log.read_text())
        self.assertEqual(json.loads(self.log.with_suffix(".activity.json").read_text())["stop_reason"], "NO_OUTPUT_PROGRESS")

    def test_cancel_stops_active_process(self):
        started = time.monotonic()
        with self.assertRaises(InterruptedError):
            self.capture("import time; [(print(n,flush=True),time.sleep(.1)) for n in range(100)]",
                         cancelled=lambda: time.monotonic() - started > .3)
        self.assertIsNotNone(self.proc.poll())
        self.assertEqual(json.loads(self.log.with_suffix(".activity.json").read_text())["stop_reason"], "CANCELLED")

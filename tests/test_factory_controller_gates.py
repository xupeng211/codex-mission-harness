"""Offline doubles only: these tests never publish a PR, contact a model or run Docker."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.adapters import GateResult
from harness.factory import Factory, FactoryBlocked, READY, git
from harness.factory_container import argv_for, run as container_run, source_fingerprint
from harness.factory_project import validate_review_limits, verify_target, FootballPredictionContract
from harness.factory_remote import Remote, identity
from harness.factory_runtime import LocalRuntime
from harness.factory_preflight import inspect_prepaid
from harness.adapters import FootballPredictionAdapter
import test_factory_project as project_fixtures


IMAGE = "sha256:" + "a" * 64
CONTAINER = {"image_id": IMAGE, "postgres_image_id": IMAGE, "profiles": ["targeted", "pr", "strict"]}
DELIVERY = {"repository": "fixture/football", "base_branch": "main"}
LIMITS = {"approval_id": "offline-test-only", "max_deepseek_chunks": 2,
          "max_canonical_diff_bytes": 100000, "allow_unknown_provider_usage": True}


class FakeRemote(Remote):
    """Explicit GitHub write double, not remote execution evidence."""
    def __init__(self, cwd, transcript, spec, target, body):
        super().__init__(cwd, transcript, 5)
        self.spec, self.target, self.body = spec, target, body
        self.branch, self.marker = identity(DELIVERY, spec, target)
        self.raw, self.branch_head, self.writes = None, None, []
        self.lose_create_response = False
        self.check_status = "PASS"
        self.adapter = type("AdapterDouble", (), {"ci": lambda s, *a, **kw:
            GateResult(self.check_status, "OFFLINE API DOUBLE", data={"head": a[1], **kw})})()

    def pull(self, head, body):
        return {"number": 7, "state": "open", "body": body,
                "head": {"sha": head, "ref": self.branch, "repo": {"full_name": DELIVERY["repository"]}},
                "base": {"sha": self.target["base"], "ref": "main", "repo": {"full_name": DELIVERY["repository"]}}}

    def api(self, endpoint, method="GET", data=None):
        if method == "POST":
            self.writes.append("create")
            self.raw = self.pull(self.target["head"], data["body"])
            if self.lose_create_response:
                raise RuntimeError("OFFLINE lost response after create")
            return copy.deepcopy(self.raw)
        if method == "PATCH":
            self.writes.append("update")
            self.raw["head"]["sha"] = self.target["head"]
            self.raw["body"] = data["body"]
            return copy.deepcopy(self.raw)
        if "/git/ref/heads/main" in endpoint:
            return {"object": {"sha": self.target["base"]}}
        if "/git/ref/heads/" in endpoint:
            return {"object": {"sha": self.branch_head}}
        if "?state=all" in endpoint:
            return [copy.deepcopy(self.raw)] if self.raw else []
        return copy.deepcopy(self.raw)

    def command(self, argv, **kwargs):
        if "ls-remote" in argv:
            return f"{self.branch_head}\trefs/heads/{self.branch}" if self.branch_head else ""
        if "push" in argv:
            self.writes.append("push")
            self.branch_head = self.target["head"]
            if self.raw:
                self.raw["head"]["sha"] = self.branch_head
        return ""


class ControllerGatesTests(unittest.TestCase):
    def setUp(self):
        # Reuse the named synthetic project fixture, without running its tests.
        self.fx = project_fixtures.ProjectContractTests("test_scope_materialized_only_in_candidate_and_bound_to_exact_head")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.fx.submit()
        self.spec, self.cwd = self.fx.f.prepare("feature")
        self.target = self.fx.f.target(self.spec, self.cwd)
        self.root = self.fx.root
        self.body = "OFFLINE test body\n" + identity(DELIVERY, self.spec, self.target)[1]

    def remote(self):
        return FakeRemote(self.cwd, self.root / "remote.log", self.spec, self.target, self.body)

    def test_container_argv_has_no_agent_socket_secrets_or_network(self):
        argv = argv_for(CONTAINER, self.cwd, "cmh-test", "targeted")
        for value in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                      "--pull=never", "-i", "--entrypoint=/usr/bin/env"):
            self.assertIn(value, argv)
        self.assertEqual(argv.count("--mount"), 2)
        # The existing project dev image keeps its locked Python QA tools here.
        # env -i must preserve this fixed image path, never the host's PATH.
        self.assertIn("PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", argv)
        self.assertIn(f"type=bind,src={self.cwd / '.git'},dst=/app/.git,readonly", argv)
        self.assertNotIn("docker.sock", str(argv))
        self.assertNotIn(str(Path.home()), str(argv))
        self.assertNotIn("--privileged", argv)
        with self.assertRaises(ValueError): argv_for(CONTAINER, self.cwd, "x", "shell")

    def test_exact_target_rejects_wrong_head_base_scope_inventory_and_dirty_source(self):
        with patch("harness.factory_project.FootballPredictionContract.policy", return_value={}):
            verify_target(self.spec, self.cwd, self.target)
            for key, value in (("head", "0" * 40), ("base", "0" * 40), ("mission_scope_sha256", "0" * 64),
                               ("files", []), ("diff_sha256", "0" * 64)):
                with self.subTest(key=key), self.assertRaises((ValueError, subprocess.SubprocessError)):
                    verify_target(self.spec, self.cwd, {**self.target, key: value})
            (self.cwd / "score.py").write_text("changed\n")
            with self.assertRaises(ValueError): verify_target(self.spec, self.cwd, self.target)

    def execute_container_double(self, mode, *, timeout=5, profile="targeted"):
        runtime = LocalRuntime()
        real_output, real_run, real_popen = subprocess.check_output, subprocess.run, subprocess.Popen
        stopped, calls, containers = [False], [], {}
        # Each operation has a distinct immutable transcript/lifecycle record.
        transcript = self.root / ("container-" + mode + ".log")
        clock = [0.0]
        class Process:
            pid = 99999999
            returncode = None
            def poll(s):
                if mode not in {"timeout", "cancel"} or stopped[0]:
                    s.returncode = -9 if stopped[0] else 0
                    if not stopped[0]:
                        containers.pop(s.name, None)  # Docker --rm on normal exit.
                return s.returncode
            def wait(s, **kwargs):
                s.returncode = -9 if stopped[0] else 0
                return s.returncode
        def popen(argv, *args, **kwargs):
            if argv[0] != "/usr/bin/docker": return real_popen(argv, *args, **kwargs)
            calls.append(argv)
            if mode == "timeout": clock[0] = 10.0
            name = argv[argv.index("--name") + 1]
            containers[name] = dict(x.split("=", 1) for i, x in enumerate(argv) if i and argv[i - 1] == "--label")
            workspace = Path(next(x.split(",dst=")[0].split("src=")[1] for x in argv if x.startswith("type=bind,") and "dst=/app" in x))
            if mode == "mutate": (workspace / "score.py").write_text("unexpected mutation\n")
            if mode == "mutate_candidate": (self.cwd / "score.py").write_text("unexpected host mutation\n")
            if mode == "cancel": runtime.container_cancel.set()
            process = Process()
            process.name = name
            read, write = os.pipe()
            os.close(write)
            process.stdout = os.fdopen(read, "rb")
            return process
        def output(argv, *args, **kwargs):
            if argv[0] == "/usr/bin/docker":
                if "image" in argv: return (IMAGE + "\n").encode()
                if "inspect" in argv: return json.dumps(containers.get(argv[-1], {})).encode()
                if "ps" in argv:
                    name = argv[argv.index("--filter") + 1].removeprefix("name=^/").removesuffix("$")
                    return name.encode() if name in containers else b""
                return b""
            return real_output(argv, *args, **kwargs)
        def command(argv, *args, **kwargs):
            if argv[0] == "/usr/bin/docker":
                calls.append(argv)
                if "create" in argv or "--detach" in argv:
                    name = argv[argv.index("--name") + 1]
                    containers[name] = dict(x.split("=", 1) for i, x in enumerate(argv) if i and argv[i - 1] == "--label")
                    if mode == "pg_start_error" and "--detach" in argv:
                        raise OSError("OFFLINE lost Docker start response")
                if "exec" in argv:
                    if mode == "pg_cancel": runtime.container_cancel.set()
                    return subprocess.CompletedProcess(argv, 1 if mode == "pg_cancel" else 0, b"" if mode == "pg_cancel" else b"1\n", b"")
                if "inspect" in argv:
                    if any("HostConfig.NetworkMode" in a for a in argv):
                        return subprocess.CompletedProcess(argv, 0, b'{"network":"none","ports":{},"mounts":[],"tmpfs":{}}', b"")
                    return subprocess.CompletedProcess(argv, 0, json.dumps(containers.get(argv[-1], {})).encode(), b"")
                if "ps" in argv:
                    name = argv[argv.index("--filter") + 1].removeprefix("name=^/").removesuffix("$")
                    return subprocess.CompletedProcess(argv, 0, name.encode() if name in containers else b"", b"")
                if "rm" in argv:
                    if mode == "pg_cleanup_failure" and argv[-1].endswith("-postgres"):
                        return subprocess.CompletedProcess(argv, 1, b"", b"OFFLINE cleanup failed")
                    containers.pop(argv[-1], None)
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            return real_run(argv, *args, **kwargs)
        with patch("harness.factory_project.FootballPredictionContract.policy", return_value={}), \
                patch("harness.factory_container.subprocess.Popen", side_effect=popen), \
                patch("harness.factory_container.subprocess.check_output", side_effect=output), \
                patch("harness.factory_container.subprocess.run", side_effect=command), \
                patch("harness.factory_container.time.monotonic", side_effect=lambda: clock[0]), \
                patch("harness.factory_container.os.killpg", side_effect=lambda *a: stopped.__setitem__(0, True)):
            result = container_run(runtime, CONTAINER, self.spec, self.cwd, self.target, ["make", "verify-" + profile],
                                   transcript, timeout)
        self.assertTrue(any("rm" in call for call in calls))
        self.assertIsNone(runtime.current_process)
        return result

    def test_pr_service_is_ready_bound_and_removed_by_same_controller(self):
        result = self.execute_container_double("pass", profile="pr")
        self.assertEqual(result["status"], "PASS")
        service = result["services"]["postgres"]
        self.assertTrue(service["ready"] and service["cleanup_confirmed"])
        self.assertEqual(service["target"], self.target)
        self.assertEqual(service["mission_id"], self.spec["mission_id"])
        self.assertEqual(service["persistent_volumes_created"], [])
        self.assertIn("--network=container:" + service["container_name"], result["argv"])
        self.assertTrue(result["temporary_directory_cleanup_confirmed"])

    def test_service_start_error_cancel_and_cleanup_failure_never_pass(self):
        for mode, status in (("pg_start_error", "BLOCKED_ENVIRONMENT"), ("pg_cancel", "CANCELLED"),
                             ("pg_cleanup_failure", "BLOCKED_ENVIRONMENT")):
            with self.subTest(mode=mode):
                (self.root / "container.log").unlink(missing_ok=True)
                result = self.execute_container_double(mode, profile="pr")
                self.assertEqual(result["status"], status)
                self.assertEqual(result["services"]["postgres"]["cleanup_confirmed"], mode != "pg_cleanup_failure")
                if mode != "pg_cleanup_failure": self.assertNotIn("argv", result)

    def test_container_double_pass_and_temporary_source_isolation(self):
        before = source_fingerprint(self.cwd, self.target["head"])
        result = self.execute_container_double("pass")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(source_fingerprint(self.cwd, self.target["head"]), before)

    def test_container_timeout_and_cancel_remove_container_and_keep_exit_evidence(self):
        for mode in ("timeout", "cancel"):
            with self.subTest(mode=mode):
                path = self.root / "container.log"
                if path.exists(): path.unlink()
                result = self.execute_container_double(mode, timeout=5)
                self.assertEqual(result["status"], "CANCELLED" if mode == "cancel" else "TIMEOUT")
                self.assertEqual(result["exit_code"], -9)
                self.assertTrue(result["cleanup_confirmed"])

    def test_container_temporary_tracked_source_mutation_fails(self):
        result = self.execute_container_double("mutate")
        self.assertEqual(result["status"], "SOURCE_CHANGED")
        self.assertFalse(result["source_unchanged"])
        self.assertFalse(git(self.cwd, "status", "--porcelain"))

    def test_candidate_source_mutation_cannot_be_pass(self):
        result = self.execute_container_double("mutate_candidate")
        self.assertEqual(result["status"], "SOURCE_CHANGED")
        self.assertEqual(result["exit_code"], 0)

    def test_pr_create_and_repeated_observation_never_duplicate_write(self):
        remote = self.remote()
        first = remote.publish(DELIVERY, self.spec, self.target, self.body)
        second = remote.publish(DELIVERY, self.spec, self.target, self.body)
        self.assertEqual(first, second)
        self.assertEqual(remote.writes, ["push", "create"])

    def test_pr_update_requires_proven_previous_head_and_exact_owned_branch(self):
        remote = self.remote()
        old = "b" * 40
        remote.raw, remote.branch_head = remote.pull(old, self.body + " old"), old
        with self.assertRaises(ValueError): remote.publish(DELIVERY, self.spec, self.target, self.body)
        self.assertEqual(remote.writes, [])
        result = remote.publish(DELIVERY, self.spec, self.target, self.body, previous_head=old)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(remote.writes, ["push", "update"])

    def test_lost_create_response_only_reconciles_read_only(self):
        remote = self.remote()
        remote.lose_create_response = True
        with self.assertRaises(RuntimeError): remote.publish(DELIVERY, self.spec, self.target, self.body)
        self.assertEqual(remote.observe(DELIVERY, self.spec, self.target, self.body)["status"], "PASS")
        self.assertEqual(remote.writes, ["push", "create"])

    def test_remote_bad_base_head_repo_body_or_closed_pr_never_passes(self):
        remote = self.remote()
        remote.publish(DELIVERY, self.spec, self.target, self.body)
        raw = copy.deepcopy(remote.raw)
        for key in ("base", "head", "repo", "body", "closed"):
            remote.raw = copy.deepcopy(raw)
            if key in {"base", "head"}: remote.raw[key]["sha"] = "f" * 40
            elif key == "repo": remote.raw["head"]["repo"]["full_name"] = "other/repo"
            elif key == "body": remote.raw["body"] += " edit"
            else: remote.raw["state"] = "closed"
            with self.subTest(key=key), self.assertRaises(ValueError):
                remote.observe(DELIVERY, self.spec, self.target, self.body)

    def test_pr_ci_delegates_exact_pr_head_and_never_turns_pending_fail_into_pass(self):
        remote = self.remote()
        remote.publish(DELIVERY, self.spec, self.target, self.body)
        for status in ("PASS", "FAIL", "PENDING", "BLOCKED_EXTERNAL"):
            remote.check_status = status
            result = remote.ci(DELIVERY, self.spec, self.target, self.body, wait=False)
            self.assertEqual(result["status"], status)
            self.assertEqual(result["ci_data"]["head"], self.target["head"])
            self.assertEqual(result["ci_data"]["pr_number"], 7)
        remote.deadline = 0
        remote.check_status = "PENDING"
        self.assertEqual(remote.ci(DELIVERY, self.spec, self.target, self.body, wait=True)["status"], "TIMEOUT")

    def test_unsupported_physical_limits_or_unaccepted_unknown_usage_block(self):
        for limits in ({**LIMITS, "max_cost_cny": 1}, {**LIMITS, "max_http_requests": 2},
                       {**LIMITS, "allow_unknown_provider_usage": False}):
            with self.assertRaises(ValueError): validate_review_limits(limits)

    def test_candidate_cannot_change_its_validation_rules_or_dependency_authority(self):
        for path in ("pytest.ini", "package.json", ".eslintrc.json", "scripts/test/run_test_suite.js",
                     "config/model_feature_contracts.json", "tests/conftest.py", ".devcontainer/Dockerfile"):
            with self.subTest(path=path), patch("harness.factory_project.subprocess.run") as run, self.assertRaises(ValueError):
                FootballPredictionContract().policy(self.spec, self.cwd, [path])
            run.assert_not_called()

    def test_original_adapter_rejects_missing_failed_skipped_and_wrong_head_required_checks(self):
        adapter = FootballPredictionAdapter()
        bound = GateResult("PASS", data={"head": self.target["head"], "base": "main", "state": "OPEN",
                                        "base_sha": self.target["base"]})
        for message, expected in (("no run for exact HEAD", "PENDING"), ("status=queued", "PENDING"),
                                  ("status=completed conclusion=failure", "FAIL"),
                                  ("status=completed conclusion=skipped", "FAIL")):
            document = {"pr": {"head_sha": self.target["head"]}, "verdict": "FAIL", "findings": [
                {"name": "required-check:Environment / Proxy / Static / Unit Gate", "passed": False, "message": message}]}
            with self.subTest(message=message), patch.object(adapter, "_pr_state", return_value=bound), \
                    patch.object(adapter, "_trusted_base_checkout", return_value=self.root), \
                    patch.object(adapter, "_call", return_value=subprocess.CompletedProcess([], 1, json.dumps(document), "")):
                result = adapter.ci(str(self.cwd), self.target["head"], 7, DELIVERY["repository"], self.target["base"])
                self.assertEqual(result.status, expected)
        for key in ("head", "base_sha"):
            bad = GateResult("PASS", data={**bound.data, key: "f" * 40})
            with patch.object(adapter, "_pr_state", return_value=bad), patch.object(adapter, "_call") as command:
                self.assertEqual(adapter.ci(str(self.cwd), self.target["head"], 7, DELIVERY["repository"], self.target["base"]).status,
                                 "BLOCKED_EXTERNAL")
                command.assert_not_called()


class LiveProtocolDouble(project_fixtures.ProjectRuntime):
    """Exercises live state transitions using explicitly named offline doubles."""
    simulation = False

    def __init__(self):
        super().__init__()
        self.remote = None
        self.fixture_remote = False

    def profile_identity(self, profile): return {"OFFLINE_DOUBLE": True}
    def project_review_admission(self, *args): return {"OFFLINE_DOUBLE": True}

    def project_review(self, *args, **kwargs):
        result = super().project_review(*args, **kwargs)
        path = Path(result["canonical_receipt"] ) if "canonical_receipt" in result else next(Path(result["evidence_dir"]).glob("*receipt.json"))
        receipt = json.loads(path.read_text())
        receipt["review_completed_at"] = "2026-10-28T00:00:00Z"
        path.write_text(json.dumps(receipt))
        result["project_evidence"] = []  # Original fixture validator checks raw receipt on every read.
        return {**result, "fixture": False, "OFFLINE_DOUBLE": True}

    def container_gate(self, policy, spec, cwd, target, command, transcript, timeout):
        transcript.write_text("OFFLINE container double; no Docker execution")
        return {"status": "PASS", "exit_code": 0, "target": target, "fixture": False,
                "profile": command[-1][7:], "image_id": IMAGE, "OFFLINE_DOUBLE": True}

    def project_remote(self, action, policy, spec, cwd, target, body, transcript, timeout, **kwargs):
        transcript.write_text("OFFLINE remote double; no GitHub writes")
        if self.remote is None:
            self.remote = FakeRemote(cwd, transcript, spec, target, body)
        self.remote.target = target
        if action == "publish": result = self.remote.publish(policy, spec, target, body, kwargs.get("previous_head"))
        elif action == "reconcile": result = self.remote.observe(policy, spec, target, body)
        else: result = self.remote.ci(policy, spec, target, body, wait=False)
        return {**result, "fixture": self.fixture_remote, "OFFLINE_DOUBLE": True}


class FactoryLiveProtocolTests(unittest.TestCase):
    def setUp(self):
        self.fx = project_fixtures.ProjectContractTests("test_scope_materialized_only_in_candidate_and_bound_to_exact_head")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.runtime = LiveProtocolDouble()
        self.config = {**self.fx.config, "simulation": False, "project_container": CONTAINER,
                       "project_delivery": DELIVERY, "project_review_limits": LIMITS,
                       "checks": [["make", "verify-targeted"]], "ci": [["make", "verify-pr"]]}
        self.f = Factory(self.fx.root / "live-protocol-double-state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        self.spec = {**self.fx.spec, "pr_body_template": "OFFLINE PR body {{candidate_head}} {{review_timestamp}}"}
        self.f.submit(self.spec)
        self.preflight = patch("harness.factory_preflight.inspect_prepaid", return_value={"status": "PASS", "findings": []})
        self.preflight.start()
        self.addCleanup(self.preflight.stop)

    def test_state_flow_current_delivery_rechecks_ci_and_candidate(self):
        report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertFalse(report["MERGE_PERFORMED"])
        self.assertFalse(report["DONE"])
        self.assertEqual(self.runtime.remote.writes, ["push", "create"])
        self.runtime.remote.check_status = "FAIL"
        self.assertNotEqual(self.f.report("feature")["DELIVERY_STATUS"], READY)
        self.runtime.remote.check_status = "PASS"
        cwd = Path(report["CANDIDATE"])
        (cwd / "score.py").write_text("def score(): return 100\n")
        self.assertNotEqual(self.f.report("feature")["DELIVERY_STATUS"], READY)

    def test_fixture_remote_cannot_grant_live_ready(self):
        self.runtime.fixture_remote = True
        report = self.f.run("feature")
        self.assertNotEqual(report["DELIVERY_STATUS"], READY)

    def test_chunk_authorization_failure_reserves_no_review_and_dispatches_nothing(self):
        spec, cwd = self.f.prepare("feature")
        target = self.f.target(spec, cwd)
        with patch.object(self.runtime, "project_review_admission", side_effect=ValueError("actual chunks exceed authorization")):
            with self.assertRaises(FactoryBlocked): self.f.project_review(spec, cwd, target, "reviewer")
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0], 0)
        self.assertEqual(self.runtime.calls, [])

    def test_preflight_recognizes_controller_path_but_missing_image_still_blocks(self):
        with patch("harness.factory_preflight.committed_text", return_value="OFFLINE dispatcher stub"), \
                patch("harness.factory_container.inspect_image", return_value=IMAGE):
            report = inspect_prepaid(self.spec, self.config)
        self.assertFalse(any(f["level"] == "HARD_BLOCKER" and f["check"] in {"checks[0]", "ci[0]"}
                             for f in report["findings"]))
        self.assertTrue(any(f.get("image_id") == IMAGE for f in report["findings"]))
        with patch("harness.factory_preflight.committed_text", return_value="OFFLINE dispatcher stub"), \
                patch("harness.factory_container.inspect_image", side_effect=FileNotFoundError("OFFLINE missing image")):
            report = inspect_prepaid(self.spec, self.config)
        self.assertEqual(report["status"], "HARD_BLOCKER")
        self.assertEqual(self.runtime.calls, [])

    def test_failed_pr_ci_returns_findings_to_rework_and_new_head_reviews(self):
        original = self.runtime.project_remote
        failed = [False]
        seen = []
        def once(action, policy, spec, cwd, target, *args, **kwargs):
            result = original(action, policy, spec, cwd, target, *args, **kwargs)
            if action == "ci":
                seen.append(target["head"])
                if not failed[0]:
                    failed[0] = True
                    return {**result, "status": "FAIL", "reason": "OFFLINE required PR CI failure"}
            return result
        original_agent = self.runtime.agent
        def rework(stage, profile, cwd, *args, **kwargs):
            result = original_agent(stage, profile, cwd, *args, **kwargs)
            if stage == "rework":
                (cwd / "score.py").write_text((cwd / "score.py").read_text() + f"\n# Offline CI repair fixture {len(seen)}\n")
            return result
        with patch.object(self.runtime, "project_remote", side_effect=once), patch.object(self.runtime, "agent", side_effect=rework):
            report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertEqual(len(seen), 2)
        self.assertNotEqual(seen[0], seen[1])
        self.assertEqual(self.runtime.remote.writes, ["push", "create", "push", "update"])
        reviews = self.f.db.execute("SELECT input FROM operations WHERE stage='review'").fetchall()
        heads = [json.loads(row[0])["target"]["head"] for row in reviews]
        for head in seen:
            self.assertEqual(heads.count(head), 2)
        self.assertTrue(all(r["target"]["head"] == seen[-1] for r in report["REVIEW_RESULT"]))
        feedback = [json.loads(row[0]) for row in self.f.db.execute("SELECT payload FROM events WHERE kind='rework'")]
        self.assertTrue(any(any(f["department"] == "pr_ci" for f in e["feedback"]) for e in feedback))

    def test_unknown_publication_reconciles_without_rewrite_or_repeated_create(self):
        original = self.runtime.project_remote
        lost = [False]
        def fail_after_create(action, *args, **kwargs):
            result = original(action, *args, **kwargs)
            if action == "publish" and not lost[0]:
                lost[0] = True
                raise RuntimeError("OFFLINE response lost")
            return result
        with patch.object(self.runtime, "project_remote", side_effect=fail_after_create):
            first = self.f.run("feature")
            self.assertEqual(first["DELIVERY_STATUS"], "UNKNOWN")
            old = dict(self.f.db.execute("SELECT * FROM operations WHERE stage='project_publish'").fetchone())
            result = self.f.run("feature")
        self.assertEqual(result["DELIVERY_STATUS"], READY, result)
        self.assertEqual(old, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (old["id"],)).fetchone()))
        self.assertEqual(self.runtime.remote.writes, ["push", "create"])


if __name__ == "__main__": unittest.main()

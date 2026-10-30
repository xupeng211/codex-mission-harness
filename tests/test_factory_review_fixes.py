"""Offline behavioral regressions for the four independent-review findings.

Only synthetic repositories, credentials and process/remote doubles are used.
The separate real Docker crash drill is delivery evidence, not a unit mock PASS.
"""
from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness.codex import AppServerCodex
from harness.factory import FactoryBlocked, READY, git
from harness.factory_container import argv_for, recover, remove_owned, resources_for
from harness.factory_remote import Remote
from harness.factory_runtime import FactoryAppServer, LocalRuntime, RuntimeFailure
from harness.factory_test_service import ProjectPostgres
import test_factory_controller_gates as controller_fixtures
from test_factory_controller_gates import CONTAINER
from test_factory_usage_scope import notification


class EarlyActivityTests(unittest.TestCase):
    def setUp(self):
        self.server = FactoryAppServer.__new__(FactoryAppServer)
        self.server.events, self.server.runtime_identity = [], {"model": "fixture"}
        self.server.token_limit, self.server.seq, self.server._end_time = 800000, 0, time.monotonic() + 5
        self.server.proc = SimpleNamespace(stdin=io.StringIO(), stdout=object())
        self.server._bind_usage_thread("root")

    def event(self, method="item/completed", turn="review", thread="root"):
        params = {"threadId": thread, "turnId": turn, "item": {"type": "agentMessage", "text": "fixture"}}
        if method.startswith("turn/"):
            params = {"threadId": thread, "turn": {"id": turn, "status": "completed"}}
        return {"method": method, "params": params}

    def accept(self, events):
        response = {"id": 1, "result": {"turn": {"id": "review"}}}
        with patch("harness.codex.AppServerCodex._read_message", side_effect=[*events, response]):
            accepted = self.server._request("turn/start", {})
            self.server._bind_usage_turn(accepted["turn"]["id"])

    def test_normal_early_mixed_activity_and_completion_survive_delayed_acceptance(self):
        events = [self.event("item/started"), notification(27), self.event("error"),
                  self.event("item/commandExecution/outputDelta"), self.event(), self.event("turn/completed")]
        self.accept(events)
        self.assertEqual(self.server._turn_completed("root", "review")["id"], "review")
        self.assertEqual(self.server.usage["total"]["totalTokens"], 27)
        self.assertEqual(self.server.usage_telemetry()["early_activity"], [e for e in events if e["method"] != "thread/tokenUsage/updated"])

    def test_early_wrong_turn_cannot_hide_in_item_error_or_terminal(self):
        for method in ("item/started", "item/completed", "error", "turn/completed", "item/agentMessage/delta"):
            with self.subTest(method=method):
                self.setUp()
                event = self.event(method, turn="other")
                with self.assertRaises(RuntimeFailure) as caught:
                    self.accept([event])
                self.assertIn(event, self.server.events)
                self.assertIn(event, caught.exception.usage_telemetry["scope_errors"])

    def test_missing_or_conflicting_identity_is_retained_and_rejected(self):
        cases = []
        for key in ("threadId", "turnId"):
            event = self.event(); del event["params"][key]; cases.append(event)
        event = self.event("turn/completed"); event["params"]["turnId"] = "contradiction"; cases.append(event)
        cases.extend([self.event(thread="child"), {"method": "error", "params": []}])
        for event in cases:
            with self.subTest(event=event):
                self.setUp()
                with self.assertRaises(RuntimeFailure) as caught: self.accept([event])
                self.assertIn(event, self.server.events)
                self.assertIn(event, caught.exception.usage_telemetry["scope_errors"])

    def test_mixed_early_turns_fail_even_when_usage_matches_accepted_turn(self):
        with self.assertRaises(RuntimeFailure):
            self.accept([self.event(), notification(20), self.event("error", turn="wrong")])

    def test_early_activity_buffer_is_bounded_by_count_and_bytes(self):
        with self.assertRaisesRegex(RuntimeFailure, "buffer exceeded"):
            for _ in range(257): self.server._observe_execution_event(self.event())
        self.assertEqual(len(self.server.usage_telemetry()["early_activity"]), 256)
        self.setUp()
        event = self.event(); event["params"]["item"]["text"] = "x" * 262144
        with self.assertRaisesRegex(RuntimeFailure, "buffer exceeded"):
            self.server._observe_execution_event(event)


class ObservationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fx = controller_fixtures.FactoryLiveProtocolTests("test_state_flow_current_delivery_rechecks_ci_and_candidate")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f, self.runtime = self.fx.f, self.fx.runtime

    def fail_then_resume(self, action):
        original = self.runtime.project_remote
        failed = [False]
        def observe(kind, *args, **kwargs):
            result = original(kind, *args, **kwargs)
            if kind == action and not failed[0]:
                failed[0] = True
                raise TimeoutError("OFFLINE read response lost")
            return result
        with patch.object(self.runtime, "project_remote", side_effect=observe):
            first = self.f.run("feature")
            self.assertEqual(first["DELIVERY_STATUS"], "UNKNOWN", first)
            old = dict(self.f.db.execute("SELECT * FROM operations WHERE status='UNKNOWN'").fetchone())
            evidence = Path(old["evidence"]).read_bytes()
            paid_before = [dict(r) for r in self.f.db.execute("SELECT * FROM operations WHERE paid=1")]
            second = self.f.run("feature")
        self.assertEqual(second["DELIVERY_STATUS"], READY, second)
        self.assertEqual(old, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (old["id"],)).fetchone()))
        self.assertEqual(evidence, Path(old["evidence"]).read_bytes())
        self.assertEqual(paid_before, [dict(r) for r in self.f.db.execute("SELECT * FROM operations WHERE paid=1")])
        self.assertEqual(self.runtime.remote.writes, ["push", "create"])
        event = json.loads(self.f.db.execute("SELECT payload FROM events WHERE kind='remote_observation_recovered'").fetchone()[0])
        self.assertEqual(event["operation_id"], old["id"])
        self.assertEqual(self.f.uncertain_operations("feature"), [])
        return old, event

    def test_failed_read_only_ci_can_resume_without_replaying_paid_or_write_operation(self):
        self.fail_then_resume("ci")

    def test_failed_final_observation_can_resume_with_original_unknown_untouched(self):
        self.fail_then_resume("verify")

    def test_failed_reconcile_with_known_pr_can_resume(self):
        self.fail_then_resume("reconcile")

    def test_recovery_is_reverified_not_granted_by_hand_written_pass_event(self):
        old, event = self.fail_then_resume("ci")
        self.f.event("feature", "remote_observation_recovered", {**event, "evidence_key": "manual-PASS"})
        self.f.db.commit()
        with self.assertRaises(FactoryBlocked): self.f.uncertain_operations("feature")
        self.assertEqual(self.f.db.execute("SELECT status FROM operations WHERE id=?", (old["id"],)).fetchone()[0], "UNKNOWN")

    def context(self):
        report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        spec, cwd = self.f.prepare("feature")
        operation = self.f.db.execute("SELECT * FROM operations WHERE stage='project_ci' ORDER BY started DESC LIMIT 1").fetchone()
        payload = json.loads(operation["input"])
        return spec, cwd, payload

    def lose_observation(self, spec, cwd, payload):
        def fail(*args, **kwargs):
            args[6].write_text("OFFLINE unknown observation, no remote mutations")
            raise TimeoutError("OFFLINE read lost")
        with patch.object(self.runtime, "project_remote", side_effect=fail), self.assertRaises(FactoryBlocked):
            self.f.project_remote_read(payload["action"], spec, cwd, payload["target"], payload["body"],
                                       payload["reviews"], expected_pr=payload["expected_pr"])
        return dict(self.f.db.execute("SELECT * FROM operations WHERE status='UNKNOWN' ORDER BY started DESC LIMIT 1").fetchone())

    def test_new_observation_must_match_pr_policy_kind_and_complete_input(self):
        spec, cwd, payload = self.context()
        old = self.lose_observation(spec, cwd, payload)
        original = self.f.db.execute("SELECT * FROM operations WHERE id=?", (old["id"],)).fetchone()
        good = self.f.db.execute("SELECT * FROM operations WHERE stage='project_ci' AND status='COMPLETE' ORDER BY started DESC LIMIT 1").fetchone()
        # A preceding success cannot reconcile a later failed observation.
        with self.assertRaises(FactoryBlocked): self.f.validate_observation_recovery("feature", original, good)
        for field, value in (("expected_pr", {**payload["expected_pr"], "pr_number": 99}),
                             ("policy", {**payload["policy"], "repository": "other/repo"}),
                             ("action", "verify"), ("target", {**payload["target"], "head": "0" * 40}),
                             ("body", payload["body"] + "changed"), ("reviews", [{"unrelated": True}])):
            changed = {**payload, field: value}
            fake = {**dict(good), "id": "synthetic-proof", "started": old["ended"] + 1,
                    "input": json.dumps(changed)}
            with self.subTest(field=field), self.assertRaises(FactoryBlocked):
                self.f.validate_observation_recovery("feature", original, fake)
        # An actual different PR response is recorded as UNKNOWN, never COMPLETE.
        original_call = self.runtime.project_remote
        def wrong_pr(*args, **kwargs): return {**original_call(*args, **kwargs), "pr_number": 99}
        with patch.object(self.runtime, "project_remote", side_effect=wrong_pr), self.assertRaises(FactoryBlocked):
            self.f.project_remote_read("ci", spec, cwd, payload["target"], payload["body"], expected_pr=payload["expected_pr"])
        self.assertIn(old["id"], {r["id"] for r in self.f.uncertain_operations("feature")})

    def test_changed_candidate_cannot_supply_a_fresh_proof_for_old_target(self):
        spec, cwd, payload = self.context()
        old = self.lose_observation(spec, cwd, payload)
        (cwd / "score.py").write_text("def score(): return 200\n")
        self.f.checkpoint(spec, cwd)
        with self.assertRaises(FactoryBlocked):
            self.f.project_remote_read("ci", spec, cwd, payload["target"], payload["body"], expected_pr=payload["expected_pr"])
        self.assertIn(old["id"], {r["id"] for r in self.f.uncertain_operations("feature")})

    def test_paid_write_running_and_unknown_pr_cannot_use_read_observation_recovery(self):
        old, event = self.fail_then_resume("ci")
        proof = self.f.db.execute("SELECT * FROM operations WHERE key=?", (event["evidence_key"],)).fetchone()
        cases = [{**old, "paid": 1}, {**old, "stage": "project_publish"}, {**old, "status": "RUNNING"},
                 {**old, "input": json.dumps({**json.loads(old["input"]), "expected_pr": None})}]
        for changed in cases:
            with self.subTest(changed=changed["stage"]), self.assertRaises(FactoryBlocked):
                self.f.validate_observation_recovery("feature", changed, proof)

    def test_tampered_fresh_evidence_cannot_resolve_unknown(self):
        old, event = self.fail_then_resume("ci")
        proof = self.f.db.execute("SELECT * FROM operations WHERE key=?", (event["evidence_key"],)).fetchone()
        evidence = Path(proof["evidence"]); evidence.chmod(0o600); evidence.write_text('{"status":"PASS"}')
        with self.assertRaises(FactoryBlocked): self.f.uncertain_operations("feature")
        self.assertEqual(self.f.db.execute("SELECT status FROM operations WHERE id=?", (old["id"],)).fetchone()[0], "UNKNOWN")

    def test_resume_attempts_only_task_cleanup_and_keeps_uncertain_validation_blocked(self):
        def interrupted(*args):
            args[5].write_text("OFFLINE interrupted Controller validation")
            raise RuntimeError("OFFLINE validation result lost")
        with patch.object(self.runtime, "container_gate", side_effect=interrupted):
            first = self.f.run("feature")
        self.assertEqual(first["DELIVERY_STATUS"], "UNKNOWN", first)
        old = dict(self.f.db.execute("SELECT * FROM operations WHERE status='UNKNOWN'").fetchone())
        paid = self.f.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0]
        with patch.object(self.runtime, "recover_container", create=True,
                          return_value={"cleanup_confirmed": False, "operation_replayed": False}) as cleanup:
            second = self.f.run("feature")
        self.assertEqual(second["DELIVERY_STATUS"], "UNKNOWN", second)
        self.assertEqual(cleanup.call_count, 1)
        self.assertEqual(cleanup.call_args.args[2], json.loads(old["input"])["target"])
        self.assertEqual(old, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (old["id"],)).fetchone()))
        self.assertEqual(paid, self.f.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0])
        evidence = json.loads(self.f.db.execute("SELECT payload FROM events WHERE kind='container_cleanup_recovered'").fetchone()[0])
        self.assertFalse(evidence["cleanup"]["cleanup_confirmed"])


class LifetimeAndAuthTests(unittest.TestCase):
    def test_targeted_lifetime_is_independent_of_postgres_and_env_precedes_timeout(self):
        with tempfile.TemporaryDirectory() as root:
            argv = argv_for(CONTAINER, Path(root), "fixture", "targeted", 3)
            self.assertEqual(argv[argv.index("/usr/bin/timeout"):],
                ["/usr/bin/timeout", "--signal=TERM", "--kill-after=5", "3", "python3", "scripts/devops/validation_profiles.py", "targeted"])
            service = ProjectPostgres(CONTAINER["postgres_image_id"], "fixture-postgres", Path(root),
                {"head": "a" * 40, "mission_scope_sha256": "b" * 64}, "fixture", None, time.monotonic() + 5, {}, io.BytesIO())
            service.evidence["ready"] = True
            argv = service.validation_argv(argv)
            self.assertLess(argv.index("DB_HOST=127.0.0.1"), argv.index("/usr/bin/timeout"))

    def test_wrong_task_labels_prevent_removal(self):
        labels = {"cmh.validation.owner": "mine", "cmh.validation.mission": "other"}
        with patch("harness.factory_container.subprocess.check_output", side_effect=[b"mine", json.dumps(labels).encode()]), \
                patch("harness.factory_container.subprocess.run") as rm:
            cleaned, _ = remove_owned("mine", "mine", {**labels, "cmh.validation.mission": "this"})
        self.assertFalse(cleaned); rm.assert_not_called()

    def test_durable_recovery_is_bound_and_does_not_replay_validation(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root); temporary = directory / "cmh-validation-12345678"; temporary.mkdir(mode=0o700)
            transcript = directory / "operation.raw"; name = "cmh-validate-" + "a" * 32
            spec = {"mission_id": "this"}; target = {"head": "a" * 40, "mission_scope_sha256": "b" * 64}
            record = {"target": target, "mission_id": "this", "policy": CONTAINER, "profile": "targeted",
                      "container_name": name, "temporary_directory": str(temporary),
                      "resources": resources_for(name, spec, target, False)}
            plan = transcript.with_suffix(".container.json"); plan.write_text(json.dumps(record)); plan.chmod(0o600)
            with patch("harness.factory_container.remove_owned", return_value=(True, 0)) as rm, \
                    patch("harness.factory_container.subprocess.Popen") as launch:
                rejected = recover(CONTAINER, {"mission_id": "other"}, target, ["make", "verify-targeted"], transcript)
                self.assertFalse(rejected["cleanup_confirmed"]); rm.assert_not_called(); self.assertTrue(temporary.exists())
                result = recover(CONTAINER, spec, target, ["make", "verify-targeted"], transcript)
                self.assertTrue(result["cleanup_confirmed"]); self.assertFalse(result["operation_replayed"])
                self.assertFalse(temporary.exists()); self.assertEqual(rm.call_count, 2); launch.assert_not_called()
            self.assertEqual(json.loads(plan.read_text()), record)

    def test_both_controller_hops_keep_only_trusted_auth_and_agents_receive_none(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); transcript = root / "remote.raw"
            credentials = {"GH_TOKEN": "synthetic-gh-only", "GITHUB_TOKEN": "synthetic-github-only", "GH_ENTERPRISE_TOKEN": "synthetic-enterprise-only"}
            host = {**credentials, "HOME": str(root), "RANDOM_PRIVATE_SECRET": "must-not-pass",
                    "PYTHONPATH": "/untrusted", "LD_PRELOAD": "/untrusted/loader.so", "GIT_CONFIG_COUNT": "1"}
            outer, inner, messages = [], [], []
            def tool(argv, **kwargs):
                inner.append(kwargs["env"])
                return subprocess.CompletedProcess(argv, 0, "{}", "")
            class Worker:
                returncode = 0
                stdin = stdout = None
                def communicate(worker, message, **kwargs):
                    messages.append(message)
                    with patch.dict(os.environ, outer[-1], clear=True), patch("harness.factory_remote.subprocess.run", side_effect=tool):
                        remote = Remote(root, transcript, 5)
                        remote.command(["/usr/bin/gh", "api", "repos/fixture/only-read"])
                    return json.dumps({"status": "PASS", "fixture": "offline-double"}), None
                def poll(worker): return 0
                def wait(worker, **kwargs): return 0
            def launch(argv, **kwargs): outer.append(kwargs["env"]); return Worker()
            with patch.dict(os.environ, host, clear=True), patch("harness.factory_runtime.subprocess.Popen", side_effect=launch):
                LocalRuntime().project_remote("ci", {}, {"mission_id": "fixture"}, root, {}, "fixture body", transcript, 5)
                # Same constructor is used for both development and review App Servers.
                agent = AppServerCodex._app_server_environment("/usr/bin/python3", codex_home=str(root / "auth"))
            self.assertEqual(len(outer), 1); self.assertEqual(len(inner), 1)
            for environment in (*outer, *inner):
                for key, value in credentials.items(): self.assertEqual(environment[key], value)
                for key in ("RANDOM_PRIVATE_SECRET", "LD_PRELOAD"): self.assertNotIn(key, environment)
                self.assertEqual(environment["GIT_CONFIG_COUNT"], "0")
            self.assertNotIn("PYTHONPATH", inner[0])
            self.assertNotEqual(outer[0]["PYTHONPATH"], "/untrusted")
            for key in credentials: self.assertNotIn(key, agent)
            saved = transcript.read_text() + transcript.with_suffix(".stderr").read_text() + str(messages)
            for value in credentials.values(): self.assertNotIn(value, saved)


if __name__ == "__main__":
    unittest.main()

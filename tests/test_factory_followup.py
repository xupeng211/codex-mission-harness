"""Zero-model regressions for the three independently checked draft leads."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness.factory_container import RedactedOutput, remove_owned, resources_for, run as container_run
from harness.factory_runtime import LocalRuntime
import test_factory_controller_gates as fixtures
import test_factory_delivery_limits as limits_fixtures


class CredentialPersistenceTests(unittest.TestCase):
    def test_every_split_and_partial_eof_retains_only_bounded_known_prefix(self):
        for secret in (b"aaa", b"abab", b"synthetic-password-123"):
            payload = b"before:" + secret + b":" + secret + b":after"
            for split in range(len(payload) + 1):
                with self.subTest(secret=secret, split=split):
                    stream = io.BytesIO(); writer = RedactedOutput(stream, secret)
                    writer.write(payload[:split])
                    self.assertNotIn(secret, stream.getvalue())
                    self.assertLess(len(writer.pending), len(secret))
                    writer.write(payload[split:]); writer.finish()
                    self.assertEqual(stream.getvalue(), b"before:[TEST_PASSWORD_REDACTED]:[TEST_PASSWORD_REDACTED]:after")
            stream = io.BytesIO(); writer = RedactedOutput(stream, secret)
            writer.write(b"diagnostic:" + secret[:2]); writer.finish()
            self.assertEqual(stream.getvalue(), b"diagnostic:[TEST_PASSWORD_REDACTED]")

    def test_split_stdout_and_stderr_are_redacted_while_validation_is_running(self):
        fx = fixtures.ControllerGatesTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        secret = "0123456789abcdef" * 3  # synthetic, never read a credential
        transcript = fx.root / "credential-output.raw"
        observed, ready = [], threading.Event()
        real_run, real_popen = subprocess.run, subprocess.Popen
        class Service:
            def __init__(s, *args):
                s.password = secret
                s.evidence = {"cleanup_confirmed": False}
            def start(s): pass
            def check(s): pass
            def validation_argv(s, argv): return argv
            def close(s): s.evidence["cleanup_confirmed"] = True
        code = ("import os,time; os.write(1,b'prefix:'); "
                f"os.write(1,{secret[:17].encode()!r}); time.sleep(.1); "
                f"os.write(1,{secret[17:].encode()!r}); "
                f"os.write(2,b' stderr:'+{secret.encode()!r}); "
                "os.write(1,b' UNKNOWN_VALUE_KEEP READY\\n'); time.sleep(.7)")
        def observe():
            until = time.monotonic() + 5
            while time.monotonic() < until:
                if transcript.exists():
                    data = transcript.read_bytes()
                    if b"READY" in data:
                        observed.append(data); ready.set(); return
                time.sleep(.01)
        observer = threading.Thread(target=observe)
        observer.start()
        def launch(argv, *args, **kw):
            if argv[0] != "/usr/bin/docker": return real_popen(argv, *args, **kw)
            return real_popen([sys.executable, "-c", code], cwd=kw["cwd"], env=kw["env"],
                              stdout=kw["stdout"], stderr=kw["stderr"], start_new_session=True)
        def command(argv, *args, **kw):
            if argv[0] == "/usr/bin/docker": return subprocess.CompletedProcess(argv, 0, b"", b"")
            return real_run(argv, *args, **kw)
        with patch("harness.factory_project.FootballPredictionContract.policy", return_value={}), \
                patch("harness.factory_container.inspect_image", return_value=fixtures.IMAGE), \
                patch("harness.factory_container.remove_owned", return_value=(True, 0)), \
                patch("harness.factory_container.ProjectPostgres", Service), \
                patch("harness.factory_container.subprocess.Popen", side_effect=launch), \
                patch("harness.factory_container.subprocess.run", side_effect=command):
            result = container_run(LocalRuntime(), fixtures.CONTAINER, fx.spec, fx.cwd, fx.target,
                                   ["make", "verify-pr"], transcript, 5)
        observer.join(5)
        self.assertTrue(ready.is_set(), "output must be persisted before process completion")
        self.assertNotIn(secret.encode(), observed[0], "finally is too late to protect a crash")
        self.assertEqual(observed[0].count(b"[TEST_PASSWORD_REDACTED]"), 2)
        self.assertIn(b"prefix:", observed[0])
        self.assertIn(b"UNKNOWN_VALUE_KEEP", observed[0])
        self.assertEqual(result["status"], "PASS", result)
        self.assertNotIn(secret, json.dumps(result))


class CancelledRecoveryTests(unittest.TestCase):
    def test_auto_removal_can_finish_after_single_rm_response_without_redeleting(self):
        labels = {"cmh.validation.owner": "mine"}
        responses = [b"mine", json.dumps(labels).encode(), b"mine", b""]
        with patch("harness.factory_container.subprocess.check_output", side_effect=responses), \
                patch("harness.factory_container.subprocess.run", return_value=subprocess.CompletedProcess([], 1)) as rm:
            cleaned, code = remove_owned("mine", "mine", labels)
        self.assertTrue(cleaned, "positive absence evidence, not rm returncode, confirms cleanup")
        self.assertEqual(code, 1)
        self.assertEqual(rm.call_count, 1)

    def setUp(self):
        self.fx = fixtures.FactoryLiveProtocolTests("test_state_flow_current_delivery_rechecks_ci_and_candidate")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f, self.runtime = self.fx.f, self.fx.runtime

    def interrupted(self):
        def crash(*args):
            args[5].write_text("synthetic interrupted validation")
            raise RuntimeError("synthetic Controller crash")
        with patch.object(self.runtime, "container_gate", side_effect=crash):
            self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        old = dict(self.f.db.execute("SELECT * FROM operations WHERE status='UNKNOWN'").fetchone())
        paid = [dict(r) for r in self.f.db.execute("SELECT * FROM operations WHERE paid=1")]
        self.f.cancel("feature")
        return old, paid

    def test_cancelled_resume_only_recovers_resources_without_replay_or_settling_unknown(self):
        old, paid = self.interrupted()
        evidence = Path(old["evidence"]).read_bytes()
        with patch.object(self.runtime, "recover_container", create=True,
                          return_value={"cleanup_confirmed": True, "operation_replayed": False}) as cleanup, \
                patch.object(self.runtime, "container_gate") as validation, \
                patch.object(self.f, "prepare", side_effect=AssertionError("cancelled resume must not prepare")):
            result = self.f.run("feature")
        self.assertEqual(result["DELIVERY_STATUS"], "CANCELLED")
        self.assertEqual(cleanup.call_count, 1)
        validation.assert_not_called()
        self.assertEqual(old, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (old["id"],)).fetchone()))
        self.assertEqual(paid, [dict(r) for r in self.f.db.execute("SELECT * FROM operations WHERE paid=1")])
        self.assertEqual(evidence, Path(old["evidence"]).read_bytes())

    def test_unconfirmed_cleanup_is_explicit_and_does_not_replay(self):
        self.interrupted()
        with patch.object(self.runtime, "recover_container", create=True,
                          return_value={"cleanup_confirmed": False, "operation_replayed": False}) as cleanup:
            report = self.f.run("feature")
        self.assertEqual(cleanup.call_count, 1)
        self.assertIn("cleanup not confirmed", " ".join(report["BLOCKERS_REMAINING"]))
        self.assertEqual(report["DELIVERY_STATUS"], "CANCELLED")

    def test_cancelled_resume_refuses_another_tasks_lifecycle_record(self):
        old, _ = self.interrupted()
        payload = json.loads(old["input"])
        transcript = self.f.root / "evidence/feature" / (old["id"] + ".raw")
        temporary = transcript.parent / "cmh-validation-12345678"; temporary.mkdir(mode=0o700)
        name = "cmh-validate-" + "e" * 32
        other = {"mission_id": "other"}
        record = {"mission_id": "other", "target": payload["target"], "policy": fixtures.CONTAINER,
                  "profile": "targeted", "container_name": name, "temporary_directory": str(temporary),
                  "resources": resources_for(name, other, payload["target"], False)}
        path = transcript.with_suffix(".container.json"); path.write_text(json.dumps(record)); path.chmod(0o600)
        with patch.object(self.runtime, "recover_container", create=True, side_effect=LocalRuntime().recover_container), \
                patch("harness.factory_container.remove_owned") as remove:
            report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "CANCELLED")
        self.assertIn("cleanup not confirmed", " ".join(report["BLOCKERS_REMAINING"]))
        remove.assert_not_called()
        self.assertTrue(temporary.exists())


class CancellationIsolationTests(unittest.TestCase):
    def setUp(self):
        self.fx = limits_fixtures.DeliveryLimitsTests("test_cancel_prevents_dispatch_and_resume_without_refund")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f, self.runtime = self.fx.f, LocalRuntime()
        # Only the Factory execution/cancellation wrapper is exercised. No
        # profile/agent/gate method is called in this synthetic body.
        self.f.runtime = self.runtime
        spec = json.loads(self.f.row("feature")["spec"])
        self.f.submit({**spec, "mission_id": "other"})

    def test_old_mission_latch_and_late_callback_cannot_cancel_new_execution(self):
        actual_cancel = self.runtime.cancel
        callbacks, old_events = [], []
        def cancel(*args, **kwargs):
            callbacks.append((args, kwargs))
            return actual_cancel(*args, **kwargs)
        def body(mission):
            if mission == "feature":
                old_events.append(self.runtime.container_cancel)
                self.f.cancel(mission)
                self.assertTrue(self.runtime.container_cancel.wait(2))
                return {"DELIVERY_STATUS": "CANCELLED"}
            self.assertFalse(self.runtime.container_cancel.is_set(), "unrelated mission inherited old cancel")
            self.assertTrue(old_events[0].is_set(), "do not clear the old task's cancellation")
            self.runtime.current_process = SimpleNamespace(pid=99999999, poll=lambda: None)
            try:
                with patch("harness.factory_runtime.os.killpg") as kill:
                    args, kwargs = callbacks[0]
                    actual_cancel(*args, **kwargs)
                    self.assertFalse(self.runtime.container_cancel.is_set())
                    kill.assert_not_called()
            finally:
                self.runtime.current_process = None
            return {"DELIVERY_STATUS": "SYNTHETIC_COMPLETED"}
        with patch.object(self.runtime, "cancel", side_effect=cancel), patch.object(self.f, "_run", side_effect=body):
            self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "CANCELLED")
            self.assertEqual(self.f.run("other")["DELIVERY_STATUS"], "SYNTHETIC_COMPLETED")

    def test_overlapping_execution_is_refused_and_only_current_token_can_cancel(self):
        first = self.runtime.begin_execution("feature")
        with self.assertRaises(RuntimeError): self.runtime.begin_execution("other")
        with self.assertRaises(RuntimeError):
            self.runtime.container_gate({}, {"mission_id": "other"}, None, None, None, None, 1)
        self.assertTrue(self.runtime.cancel(first))
        self.assertTrue(first.is_set())
        self.runtime.end_execution(first)
        second = self.runtime.begin_execution("other")
        try:
            self.assertFalse(self.runtime.cancel(first))
            self.assertFalse(self.runtime.cancel())
            self.assertFalse(second.is_set())
            self.runtime.end_execution(first)  # stale completion also has no authority
            self.assertTrue(self.runtime.cancel(second))
            self.assertTrue(second.is_set())
        finally:
            self.runtime.end_execution(second)


if __name__ == "__main__":
    unittest.main()

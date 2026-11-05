"""Real local trees with synthetic Python workloads; no model/auth/network.

Original AppServerProcess supervision and durable verifier are exercised.
Faults marked injected substitute acknowledgement/integrity, not stop success.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from harness.adapters import FootballPredictionAdapter
from harness.appserver_process import AppServerProcess, process_identity, validate_supervised_stop
from harness.factory_project import FootballPredictionContract, review_process_binding, validate_review_stop
from harness.factory_runtime import LocalRuntime, RuntimeFailure


def offline_review_summaries(root, spec, cwd, target):
    """Real local stop proofs, absent receipts: never a canonical approval."""
    import uuid
    summaries = []
    runtime = LocalRuntime()
    for lane in ("reviewer", "second_reviewer"):
        raw = Path(root) / (uuid.uuid4().hex + ".raw")
        evidence = raw.with_suffix(".retained")
        evidence.mkdir(mode=0o700)
        argv = [sys.executable, "-I", "-B", "-c", "pass"]
        result = {"stdout_path": str(raw), "stderr_path": str(raw.with_suffix(".review.stderr")),
                  "evidence_dir": str(evidence), "executed_runner_argv": argv, "exit_code": 0}
        binding = review_process_binding(spec, cwd, target, lane, result)
        _, proof = runtime._supervised_review_step(binding, argv, cwd,
            {"PATH": "/usr/bin:/bin"}, raw.with_suffix(".review"), 3)
        raw.write_text(""); raw.chmod(0o600)
        result["review_lifecycle"] = proof
        summaries.append({"lane": lane, "canonical_execution": result,
            "canonical_receipt": str(evidence / "MISSING-receipt.json"),
            "canonical_receipt_data": {"review_completed_at": "2026-10-28T00:00:00Z"}})
    return summaries


class ReviewLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="review-lifecycle-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cwd = self.root / "candidate"
        self.cwd.mkdir(mode=0o700)
        self.runtime = LocalRuntime()

    def run_step(self, name="one", code="pass", timeout=3):
        argv = [sys.executable, "-I", "-B", "-c", code]
        binding = {"stage": "offline-local-test", "operation": name, "argv": argv,
                   "mission": "fixture", "target": {"head": "a" * 40}}
        result = self.runtime._supervised_review_step(binding, argv, self.cwd,
            {"PATH": "/usr/bin:/bin"}, self.root / name, timeout)
        return binding, result

    def test_parent_exit_detached_descendant_still_live_before_stop(self):
        info = self.root / "child.pid"
        code = f'''import os,time,signal
from pathlib import Path
if os.fork()==0:
 os.setsid()
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 Path({str(info)!r}).write_text(str(os.getpid()))
 while True:time.sleep(.01)
while not Path({str(info)!r}).exists():time.sleep(.005)
'''
        original = AppServerProcess.stop
        observations = []
        def stop(owner):
            observations.append(process_identity(int(info.read_text()))["state"])
            return original(owner)
        with patch.object(AppServerProcess, "stop", stop):
            binding, (status, proof) = self.run_step(code=code)
        self.assertEqual(status, 0)
        self.assertNotIn(observations[0], ("Z", "X"))
        self.assertFalse(Path("/proc/" + info.read_text()).exists())
        self.assertEqual(validate_supervised_stop(proof, binding), 0)
        doc = json.loads(Path(proof["path"]).read_text())
        self.assertEqual(doc["stop"]["proof"], "ECHILD")
        self.assertGreaterEqual(len(doc["stop"]["reaped"]), 2)

    def test_binding_and_other_operation_proofs_cannot_be_borrowed(self):
        binding, (_, proof) = self.run_step()
        for key, value in (("operation", "other"), ("mission", "other"),
                           ("target", {"head": "b" * 40}), ("argv", ["other"])):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_supervised_stop(proof, {**binding, key: value})
        self.run_step(name="two")
        with self.assertRaises(RuntimeError):
            validate_supervised_stop(proof, {**binding, "operation": "two"})
        path = Path(proof["path"])
        path.write_text(path.read_text() + " ")
        with self.assertRaises(RuntimeError): validate_supervised_stop(proof, binding)

    def test_timeout_and_cancel_stop_tree_but_never_supply_consumable_verdict(self):
        with self.assertRaisesRegex(RuntimeFailure, "timeout"):
            self.run_step(code="import time; time.sleep(30)", timeout=.05)
        doc = json.loads((self.root / "one.stop.json").read_text())
        self.assertEqual(doc["stop"]["proof"], "ECHILD")
        proof = {"path": str(self.root / "one.stop.json"), "sha256": hashlib.sha256((self.root / "one.stop.json").read_bytes()).hexdigest()}
        binding = {k: v for k, v in doc["binding"].items() if k != "execution_id"}
        with self.assertRaises(RuntimeError): validate_supervised_stop(proof, binding)
        errors = []
        def worker():
            try: self.run_step(name="cancel", code="import time; time.sleep(30)")
            except BaseException as exc: errors.append(exc)
        thread = threading.Thread(target=worker)
        thread.start()
        deadline = time.monotonic() + 3
        while self.runtime._review_owner is None and time.monotonic() < deadline: time.sleep(.005)
        self.runtime.cancel()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIn("cancelled", str(errors[0]))
        self.assertEqual(json.loads((self.root / "cancel.stop.json").read_text())["stop"]["proof"], "ECHILD")
        self.assertIsNone(self.runtime._review_owner)

    def test_injected_unknown_keeps_evidence_slot_and_no_replacement_dispatch(self):
        original = AppServerProcess.stop
        def unknown(owner):
            original(owner)  # test cleanup is real; acknowledgement acceptance is the fault
            raise RuntimeError("injected stop UNKNOWN")
        with patch.object(AppServerProcess, "stop", unknown), self.assertRaisesRegex(RuntimeError, "UNKNOWN"):
            self.run_step()
        self.assertTrue((self.root / "one.process.jsonl").exists())
        self.assertFalse((self.root / "one.stop.json").exists())
        self.assertIsNotNone(self.runtime.unconfirmed_appserver())
        with self.assertRaises(RuntimeFailure): self.run_step(name="replacement")
        with self.assertRaises(RuntimeError): self.runtime.begin_execution("other")

    def assert_startup_failed(self, log, argv, cwd, *, request=None):
        binding = {"stage": "canonical-review", "mission": "fixture",
                   "lifecycle": str(log), "argv": argv}
        with patch("harness.factory_runtime.validate_supervised_stop") as consumer:
            with self.assertRaises(RuntimeFailure) as caught:
                self.runtime._supervised_review_step(binding, argv, cwd,
                    {"PATH": "/usr/bin:/bin"}, log, 3, request=request)
            consumer.assert_not_called()
        error = caught.exception
        self.assertIn("startup failed before payload confirmation", str(error))
        self.assertIsNotNone(error.__cause__, "preserve the actual startup error explicitly")
        self.assertFalse(log.with_suffix(log.suffix + ".stop.json").exists(),
                         "an incomplete start must not acquire a canonical completion record")
        self.assertIsNotNone(self.runtime.unconfirmed_appserver())
        with self.assertRaises(RuntimeError): self.runtime.begin_execution("replacement")
        return error, self.runtime._review_owner

    def test_no_supervisor_start_preserves_error_and_not_started_without_fabricating_echild(self):
        for request_present in (False, True):
            with self.subTest(request=request_present):
                self.runtime = LocalRuntime()
                log = self.root / (("a" if request_present else "b") * 32 + ".review")
                path = log.with_suffix(".input.json")
                request = (path, b"{}") if request_present else None
                error, owner = self.assert_startup_failed(log,
                    [sys.executable, "-I", "-B", "-c", "pass"], self.cwd / "absent", request=request)
                self.assertIsInstance(error.__cause__, FileNotFoundError)
                self.assertIsNone(owner.proc)
                self.assertEqual(owner.stopped["proof"], "not_started")
                self.assertEqual(owner.stopped["binding"], owner.binding)
                self.assertIn("stop=not_started", str(error))
                self.assertFalse(log.with_suffix(log.suffix + ".process.jsonl").exists())
                if request_present:
                    self.assertEqual(path.read_bytes(), b"{}", "retain the original request")
                    with self.assertRaisesRegex(RuntimeFailure, "UNKNOWN"):
                        LocalRuntime().assert_canonical_lifecycles(self.root, "fixture")

    def test_real_supervisor_payload_exec_failure_keeps_startup_diagnosis_and_echild_original(self):
        log = self.root / ("c" * 32 + ".review")
        error, owner = self.assert_startup_failed(log, [str(self.root / "no-executable")], self.cwd)
        self.assertIn("payload startup unconfirmed", str(error.__cause__))
        self.assertEqual(owner.stopped["proof"], "ECHILD")
        self.assertEqual(owner.stopped["reaped"], [])
        self.assertEqual(owner.proc.returncode, 0)
        self.assertFalse(Path(f"/proc/{owner.proc.pid}").exists())
        with self.assertRaisesRegex(RuntimeFailure, "UNKNOWN"):
            LocalRuntime().assert_canonical_lifecycles(self.root, "fixture")

    def test_startup_ack_binding_faults_stop_real_tree_before_reporting_incomplete_identity(self):
        import harness.appserver_process as protocol
        receive = protocol._receive
        for event in ("ready", "started", "started_receive_error"):
            with self.subTest(event=event):
                self.runtime = LocalRuntime()
                log = self.root / ({"ready": "d", "started": "e", "started_receive_error": "9"}[event] * 32 + ".review")
                def mismatch(channel):
                    value = receive(channel)
                    if event == "started_receive_error" and value.get("event") == "started":
                        raise TimeoutError("injected startup acknowledgement receive failure")
                    return {**value, "binding": {"wrong": "operation"}} if value.get("event") == event else value
                with patch.object(protocol, "_receive", side_effect=mismatch):
                    error, owner = self.assert_startup_failed(log,
                        [sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"], self.cwd)
                if event == "started_receive_error":
                    self.assertIsInstance(error.__cause__, TimeoutError)
                    self.assertIn("acknowledgement receive failure", str(error.__cause__))
                else:
                    self.assertIn("handshake differs" if event == "ready" else "payload startup unconfirmed",
                                  str(error.__cause__))
                self.assertEqual(owner.stopped["proof"], "ECHILD")
                self.assertEqual(owner.proc.returncode, 0)
                self.assertFalse(Path(f"/proc/{owner.proc.pid}").exists())
                self.assertEqual(len(owner.stopped["reaped"]), int(event != "ready"))
                for child in owner.stopped["reaped"]:
                    self.assertFalse(Path(f"/proc/{child['pid']}").exists())
                with self.assertRaisesRegex(RuntimeFailure, "UNKNOWN"):
                    LocalRuntime().assert_canonical_lifecycles(self.root, "fixture")

    def test_startup_and_stop_binding_fault_preserves_sticky_unknown_before_payload_access(self):
        import harness.appserver_process as protocol
        receive = protocol._receive
        originals = []
        def mismatch(channel):
            value = receive(channel)
            originals.append(value)
            if value.get("event") in ("started", "stopped"):
                return {**value, "binding": {"wrong": "operation"}}
            return value
        log = self.root / ("f" * 32 + ".review")
        argv = [sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"]
        try:
            with patch.object(protocol, "_receive", side_effect=mismatch), \
                    self.assertRaisesRegex(RuntimeError, "AppServer stop UNKNOWN") as caught:
                self.runtime._supervised_review_step(
                    {"stage": "canonical-review", "mission": "fixture", "lifecycle": str(log), "argv": argv},
                    argv, self.cwd, {"PATH": "/usr/bin:/bin"}, log, 3)
            owner = self.runtime._review_owner
            self.assertIsNone(owner.stopped)
            self.assertIsNotNone(owner.failure)
            self.assertIsNone(owner.proc.returncode, "UNKNOWN must not release the supervisor")
            self.assertIsNotNone(caught.exception.__cause__)
            with self.assertRaisesRegex(RuntimeError, "UNKNOWN"): owner.stop()
            with self.assertRaises(RuntimeError): self.runtime.begin_execution("replacement")
            with self.assertRaisesRegex(RuntimeFailure, "UNKNOWN"):
                LocalRuntime().assert_canonical_lifecycles(self.root, "fixture")
            self.assertFalse(log.with_suffix(log.suffix + ".stop.json").exists())
        finally:
            # Test-only exact-resource teardown: the real, unmodified reply is
            # known to this fault injector, NOT accepted by the runtime. No
            # product failure flag or completion record is changed/repaired.
            owner = self.runtime._review_owner
            stopped = [v for v in originals if v.get("event") == "stopped"]
            if owner is not None and stopped and stopped[-1].get("proof") == "ECHILD":
                self.assertEqual(stopped[-1]["binding"], owner.binding)
                protocol._send(owner.channel, {"command": "release", "binding": owner.binding})
                self.assertEqual(owner.proc.wait(timeout=2), 0)
                owner.channel.close()
                os.close(owner.pidfd)

    def test_restart_cannot_bypass_pending_validator_or_borrow_another_stop(self):
        spec, target = {"mission_id": "fixture"}, {"base": "a" * 40, "head": "b" * 40}
        reviews = offline_review_summaries(self.root, spec, self.cwd, target)
        runtime = LocalRuntime()  # no in-memory owner inherited
        runtime.assert_canonical_lifecycles(self.root, "fixture")
        pending = self.root / ("0" * 32 + ".validator-" + "1" * 32 + ".input.json")
        pending.write_text("{}"); pending.chmod(0o600)
        before = set(self.root.iterdir())
        with patch.object(AppServerProcess, "start") as dispatch:
            with self.assertRaisesRegex(RuntimeFailure, "UNKNOWN"):
                runtime.project_validate_review(spec, self.cwd, target, "reviewer", reviews[0]["canonical_execution"])
            dispatch.assert_not_called()
        self.assertEqual(before, set(self.root.iterdir()), "no retro-signing or replacement validation")
        pending.unlink()  # remove only this test's injected pre-launch crash fixture
        first, second = [Path(r["canonical_execution"]["review_lifecycle"]["path"]) for r in reviews]
        second.write_bytes(first.read_bytes())
        with self.assertRaisesRegex(RuntimeFailure, "UNKNOWN"):
            runtime.assert_canonical_lifecycles(self.root, "fixture")

    def test_validator_descendants_stop_before_gate_result_is_returned(self):
        """Only the consumer workload is substituted; real supervision runs."""
        spec, target = {"mission_id": "fixture"}, {"base": "a" * 40, "head": "b" * 40}
        result = offline_review_summaries(self.root, spec, self.cwd, target)[0]["canonical_execution"]
        info = self.root / "validator-child.pid"
        workload = f'''import os,time,json
from pathlib import Path
if os.fork()==0:
 os.setsid()
 Path({str(info)!r}).write_text(str(os.getpid()))
 while True:time.sleep(.01)
while not Path({str(info)!r}).exists():time.sleep(.005)
print(json.dumps({{"status":"PASS","evidence":"OFFLINE consumer workload only","artifact":None,"data":{{"fixture":True}}}}))
'''
        original = self.runtime._supervised_review_step
        def step(binding, argv, *args, **kwargs):
            self.assertEqual(binding["stage"], "canonical-validator")
            self.assertEqual(binding["review_lifecycle"], result["review_lifecycle"])
            argv = [sys.executable, "-I", "-B", "-c", workload]
            return original({**binding, "argv": argv}, argv, *args, **kwargs)
        with patch("harness.factory_project.verify_target"), \
                patch.object(FootballPredictionAdapter, "review_environment", return_value={"PATH": "/usr/bin:/bin"}), \
                patch.object(self.runtime, "_supervised_review_step", side_effect=step):
            checked = self.runtime.project_validate_review(spec, self.cwd, target, "reviewer", result)
        self.assertEqual(checked.status, "PASS")
        self.assertFalse(Path("/proc/" + info.read_text()).exists())
        self.assertTrue(all(Path(v["path"]).is_file() for v in checked.validation_evidence))
        self.assertEqual(json.loads(Path(checked.validation_lifecycle["path"]).read_text())["stop"]["proof"], "ECHILD")

    def test_original_consumer_requires_same_operation_stop_before_any_receipt_read(self):
        spec, target = {"mission_id": "fixture"}, {"base": "a" * 40, "head": "b" * 40}
        evidence = self.root / "retained"
        evidence.mkdir(mode=0o700)
        raw = self.root / "op.raw"
        argv = [sys.executable, "-I", "-B", "-c", "print('offline runner')"]
        result = {"stdout_path": str(raw), "stderr_path": str(self.root / "op.review.stderr"),
                  "evidence_dir": str(evidence), "executed_runner_argv": argv, "exit_code": 0}
        binding = review_process_binding(spec, self.cwd, target, "reviewer", result)
        _, proof = self.runtime._supervised_review_step(binding, argv, self.cwd,
            {"PATH": "/usr/bin:/bin"}, raw.with_suffix(".review"), 3)
        raw.write_bytes(raw.with_suffix(".review").read_bytes()); raw.chmod(0o600)
        result["review_lifecycle"] = proof
        self.assertEqual(validate_review_stop(spec, self.cwd, target, "reviewer", result), 0)
        adapter = FootballPredictionAdapter()
        contract = FootballPredictionContract(adapter)
        with patch.object(adapter, "review_result") as consumer:
            for lane, altered in (("second_reviewer", result), ("reviewer", {**result, "review_lifecycle": {**proof, "sha256": "0" * 64}}),
                                  ("reviewer", {k: v for k, v in result.items() if k != "review_lifecycle"})):
                with self.assertRaises((RuntimeError, ValueError, KeyError)):
                    contract.validate_review(spec, self.cwd, target, lane, altered)
            consumer.assert_not_called()
        # Recovery reuses originals; no helper is started to retro-sign missing proof.
        with patch.object(AppServerProcess, "start") as dispatch:
            with self.assertRaises(KeyError): self.runtime.project_validate_review(spec, self.cwd, target, "reviewer", {})
            dispatch.assert_not_called()


if __name__ == "__main__": unittest.main()

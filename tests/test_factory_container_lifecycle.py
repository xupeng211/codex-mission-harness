"""Local Docker doubles and real disposable clients; no daemon or model calls."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from harness.factory import git
from harness.factory_container import remove_owned
from harness.factory_runtime import LocalRuntime
import test_factory_controller_gates as fixtures

CONTAINER, IMAGE = fixtures.CONTAINER, fixtures.IMAGE


class DockerDouble:
    def __init__(self, fixture, runtime, mode="normal"):
        self.fx, self.runtime, self.mode = fixture, runtime, mode
        self.calls, self.clients, self.resources = [], [], {}
        self.ready = threading.Event()
        self.offset, self.cleanup_blocked = 0, False
        self.real_run, self.real_popen = subprocess.run, subprocess.Popen
        self.real_output, self.clock = subprocess.check_output, time.monotonic

    def cloned(self, cwd, *args):
        result = git(cwd, *args)
        if args[0] == "clone":
            if self.mode == "clone_cancel":
                self.runtime.container_cancel.set()
            if self.mode == "clone_deadline":
                self.offset = 10
        return result

    def dispatch(self, argv, **kwargs):
        phase = argv[1]
        self.calls.append((phase, argv))
        if phase in {"create", "run"}:
            name = argv[argv.index("--name") + 1]
            self.resources[name] = {x.split("=", 1)[0]: x.split("=", 1)[1]
                                    for i, x in enumerate(argv) if i and argv[i - 1] == "--label"}
        blocked = self.mode == phase + "_blocked"
        client = self.real_popen(["/usr/bin/python3", "-B", "-c", "import time; time.sleep(30)"]
                                 if blocked else ["/usr/bin/true"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True,
                                 env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.clients.append(client)
        if blocked:
            self.ready.set()
        if phase == "create" and self.mode == "create_cancel":
            self.runtime.container_cancel.set()
        if phase == "cp" and self.mode == "cp_cancel":
            self.runtime.container_cancel.set()
        if phase == "cp" and self.mode == "cp_deadline":
            self.offset = 10
        return client

    def popen(self, argv, *args, **kwargs):
        if argv[0] != "/usr/bin/docker":
            return self.real_popen(argv, *args, **kwargs)
        return self.dispatch(argv, **kwargs)

    def command(self, argv, *args, **kwargs):
        if argv[0] != "/usr/bin/docker":
            return self.real_run(argv, *args, **kwargs)
        if argv[1] == "rm":
            self.calls.append(("rm", argv))
            self.resources.pop(argv[-1], None)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        # Also exercise the old synchronous preparation before the fix.
        client = self.dispatch(argv, **kwargs)
        try:
            code = client.wait(timeout=min(2, kwargs.get("timeout", 2)))
        finally:
            if client.poll() is None:
                os.killpg(client.pid, signal.SIGKILL)
                client.wait()
            client.stdout.close()
        if kwargs.get("check") and code:
            raise subprocess.CalledProcessError(code, argv)
        return subprocess.CompletedProcess(argv, code, b"", b"")

    def output(self, argv, *args, **kwargs):
        if argv[0] != "/usr/bin/docker":
            return self.real_output(argv, *args, **kwargs)
        if argv[1] == "ps":
            name = argv[argv.index("--filter") + 1].removeprefix("name=^/").removesuffix("$")
            return name.encode() if name in self.resources else b""
        if argv[1] == "inspect":
            return json.dumps(self.resources[argv[-1]]).encode()
        raise AssertionError(argv)

    def remove(self, name, owner, labels):
        if self.cleanup_blocked and name.endswith("-dependencies"):
            return False, None
        return remove_owned(name, owner, labels)

    def hooks(self):
        stack = ExitStack()
        for name, value in (("harness.factory_project.FootballPredictionContract.policy", lambda *a: {}),
                            ("harness.factory_container.inspect_image", lambda *a: IMAGE),
                            ("harness.factory.git", self.cloned),
                            ("harness.factory_container.subprocess.Popen", self.popen),
                            ("harness.factory_container.subprocess.run", self.command),
                            ("harness.factory_container.subprocess.check_output", self.output),
                            ("harness.factory_container.remove_owned", self.remove),
                            ("harness.factory_container.time.monotonic", lambda: self.clock() + self.offset)):
            stack.enter_context(patch(name, side_effect=value))
        return stack

    def close(self):
        for client in self.clients:
            if client.poll() is None:
                os.killpg(client.pid, signal.SIGKILL)
            client.wait(timeout=3)
            if client.stdout is not None:
                client.stdout.close()


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.runtime = LocalRuntime()
        self.double = DockerDouble(self.fx, self.runtime)
        self.addCleanup(self.double.close)

    def gate(self, timeout=5):
        return self.runtime.container_gate(CONTAINER, self.fx.spec, self.fx.cwd, self.fx.target,
                                           ["make", "verify-targeted"], self.fx.root / "gate.raw", timeout)

    def test_clone_cancellation_prevents_all_dependency_dispatch(self):
        self.double.mode = "clone_cancel"
        with self.double.hooks(): result = self.gate()
        self.assertEqual(result["status"], "CANCELLED")
        self.assertEqual(self.double.calls, [])

    def test_clone_deadline_prevents_all_dependency_dispatch(self):
        self.double.mode = "clone_deadline"
        with self.double.hooks(): result = self.gate()
        self.assertEqual(result["status"], "TIMEOUT")
        self.assertEqual(self.double.calls, [])

    def test_cancellation_after_create_skips_copy_and_cleans_resource(self):
        self.double.mode = "create_cancel"
        with self.double.hooks(): result = self.gate()
        self.assertEqual(result["status"], "CANCELLED")
        self.assertEqual([p for p, _ in self.double.calls if p != "rm"], ["create"])
        self.assertEqual(self.double.resources, {})
        self.assertTrue(result["dependencies_cleanup_confirmed"])

    def test_cancellation_after_copy_prevents_validation(self):
        self.double.mode = "cp_cancel"
        with self.double.hooks(): result = self.gate()
        self.assertEqual(result["status"], "CANCELLED")
        self.assertEqual([p for p, _ in self.double.calls if p != "rm"], ["create", "cp"])
        self.assertFalse(self.double.resources)

    def test_deadline_after_copy_prevents_validation(self):
        self.double.mode = "cp_deadline"
        with self.double.hooks(): result = self.gate()
        self.assertEqual(result["status"], "TIMEOUT")
        self.assertNotIn("run", [p for p, _ in self.double.calls])
        self.assertFalse(self.double.resources)

    def blocked_client(self, phase, cancel):
        self.double.mode = phase + "_blocked"
        results, errors = [], []
        def work():
            try: results.append(self.gate(5 if cancel else 0.3))
            except BaseException as error: errors.append(error)
        worker = threading.Thread(target=work)
        with self.double.hooks():
            worker.start()
            try:
                self.assertTrue(self.double.ready.wait(2))
                client = self.double.clients[-1]
                if cancel:
                    # A stale identity has no authority over this preparation.
                    self.assertFalse(self.runtime.cancel(threading.Event()))
                    self.assertIsNone(client.poll())
                    self.assertTrue(self.runtime.cancel(self.runtime.container_cancel))
                worker.join(0.8)
                self.assertFalse(worker.is_alive(), "preparation client ignored cancellation/deadline")
                self.assertIsNotNone(client.poll(), "client must be reaped, not just report a status")
            finally:
                self.double.close()
                worker.join(3)
        self.assertFalse(errors, errors)
        self.assertEqual(results[0]["status"], "CANCELLED" if cancel else "TIMEOUT")
        self.assertIsNone(self.runtime.current_process)
        self.assertFalse(self.double.resources)
        self.assertNotIn("run", [p for p, _ in self.double.calls])

    def test_create_client_is_stopped_on_cancel(self): self.blocked_client("create", True)
    def test_copy_client_is_stopped_on_cancel(self): self.blocked_client("cp", True)
    def test_create_client_uses_remaining_deadline(self): self.blocked_client("create", False)
    def test_copy_client_uses_remaining_deadline(self): self.blocked_client("cp", False)

    def test_normal_path_and_execution_identity_remain_usable(self):
        with self.double.hooks(): result = self.gate()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual([p for p, _ in self.double.calls if p != "rm"], ["create", "cp", "run"])
        self.assertIsNone(self.runtime.current_process)
        self.assertIsNone(self.runtime._active_execution)
        self.assertFalse(self.double.resources)


class CompletedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.FactoryLiveProtocolTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f = self.fx.f
        self.spec, self.cwd = self.f.prepare("feature")
        self.target = self.f.target(self.spec, self.cwd)
        self.runtime = self.f.runtime = LocalRuntime()
        self.double = DockerDouble(self, self.runtime)
        self.addCleanup(self.double.close)

    def completed(self, cleanup=True, wrong_record=False):
        self.double.cleanup_blocked = not cleanup
        def invoke(transcript):
            result = self.runtime.container_gate(CONTAINER, self.spec, self.cwd, self.target,
                                                ["make", "verify-targeted"], transcript, 5)
            if wrong_record:
                path = Path(result["lifecycle_record"])
                record = json.loads(path.read_text())
                record["target"]["head"] = "0" * 40
                path.write_text(json.dumps(record))
            return result
        with self.double.hooks():
            result = self.f.operation("feature", "lifecycle-check", "checks", "local", {"target": self.target},
                {"target": self.target, "command": ["make", "verify-targeted"]}, False,
                invoke)
        self.double.cleanup_blocked = False
        row = dict(self.f.db.execute("SELECT * FROM operations WHERE key='lifecycle-check'").fetchone())
        self.assertEqual(row["status"], "COMPLETE")
        return result, row

    def test_complete_cleanup_failure_is_recovered_without_changing_original(self):
        result, row = self.completed(cleanup=False)
        self.assertEqual(result["status"], "BLOCKED_ENVIRONMENT")
        raw = {Path(p["path"]): Path(p["path"]).read_bytes() for p in result["raw_evidence"]}
        raw[Path(row["evidence"])] = Path(row["evidence"]).read_bytes()
        with self.double.hooks(), patch.object(self.runtime, "container_gate") as validate:
            cleanup = self.f.recover_interrupted_containers("feature")
            validate.assert_not_called()
        self.assertEqual(len(cleanup), 1)
        self.assertTrue(cleanup[0]["cleanup_confirmed"], cleanup)
        self.assertFalse(self.double.resources)
        self.assertEqual(row, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (row["id"],)).fetchone()))
        for path, original in raw.items(): self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0], 0)
        with patch.object(self.runtime, "container_gate", side_effect=AssertionError("no replay")):
            cached = self.f.operation("feature", row["key"], "checks", "local", {}, {}, False,
                                      lambda *a: self.fail("validation replayed"))
        self.assertEqual(cached, result)
        self.double.calls.clear()
        with self.double.hooks(): self.f.recover_interrupted_containers("feature")
        self.assertNotIn("rm", [p for p, _ in self.double.calls], "absence needs no destructive retry")

    def test_cancelled_resume_cleans_complete_operation_without_prepare_or_dispatch(self):
        _, row = self.completed(cleanup=False)
        self.f.cancel("feature")
        with self.double.hooks(), patch.object(self.f, "prepare", side_effect=AssertionError("no prepare")), \
                patch.object(self.runtime, "container_gate", side_effect=AssertionError("no validation")), \
                patch.object(self.f, "agent", side_effect=AssertionError("no paid dispatch")), \
                patch.object(self.runtime, "project_remote", side_effect=AssertionError("no remote")):
            result = self.f.run("feature")
        self.assertEqual(result["DELIVERY_STATUS"], "CANCELLED")
        self.assertFalse(self.double.resources)
        self.assertEqual(row, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (row["id"],)).fetchone()))

    def test_wrong_live_ownership_is_not_removed(self):
        _, _row = self.completed(cleanup=False)
        for labels in self.double.resources.values(): labels["cmh.validation.mission"] = "other"
        self.double.calls.clear()
        with self.double.hooks(): cleanup = self.f.recover_interrupted_containers("feature")
        self.assertEqual(len(cleanup), 1)
        self.assertFalse(cleanup[0]["cleanup_confirmed"])
        self.assertTrue(self.double.resources)
        self.assertNotIn("rm", [p for p, _ in self.double.calls])

    def test_incomplete_lifecycle_proof_is_explicit_and_not_removed(self):
        result, _row = self.completed(cleanup=False)
        Path(result["lifecycle_record"]).unlink()
        self.double.calls.clear()
        with self.double.hooks(): cleanup = self.f.recover_interrupted_containers("feature")
        self.assertEqual(len(cleanup), 1)
        self.assertFalse(cleanup[0]["cleanup_confirmed"])
        self.assertTrue(self.double.resources)
        self.assertEqual(self.double.calls, [])

    def test_wrong_lifecycle_target_is_not_removed(self):
        self.completed(cleanup=False, wrong_record=True)
        with self.double.hooks(): cleanup = self.f.recover_interrupted_containers("feature")
        self.assertEqual(len(cleanup), 1)
        self.assertFalse(cleanup[0]["cleanup_confirmed"])
        self.assertTrue(self.double.resources)

    def test_already_confirmed_cleanup_needs_no_recovery(self):
        self.completed()
        self.double.calls.clear()
        with self.double.hooks(): self.assertEqual(self.f.recover_interrupted_containers("feature"), [])
        self.assertEqual(self.double.calls, [])

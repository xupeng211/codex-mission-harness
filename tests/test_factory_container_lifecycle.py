"""Local Docker doubles and real disposable clients; no daemon or model calls."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import traceback
import unittest
from unittest.mock import patch

from harness import factory_container
from harness.factory_container import remove_owned, _ClientStops
from harness.factory_runtime import LocalRuntime
import test_factory_controller_gates as fixtures

CONTAINER, IMAGE = fixtures.CONTAINER, fixtures.IMAGE


def seal_no_clients(transcript, record):
    """Directory-identity fixtures explicitly launch no clients; close that plan.

    Full gate/Factory tests below and in recovery_stops exercise real clients.
    This uses the product writer, not a fabricated successful process stop.
    """
    runtime = LocalRuntime()
    execution = runtime.begin_execution(record["mission_id"])
    clients = _ClientStops(runtime, transcript, record, transcript.with_suffix(".container.json").read_bytes())
    try:
        return clients.seal()
    finally:
        clients.close()
        runtime.end_execution(execution)


class DockerDouble:
    def __init__(self, fixture, runtime, mode="normal"):
        self.fx, self.runtime, self.mode = fixture, runtime, mode
        self.calls, self.clients, self.resources = [], [], {}
        self.ready = threading.Event()
        self.offset, self.cleanup_blocked = 0, False
        self.real_run, self.real_popen = subprocess.run, subprocess.Popen
        self.real_output, self.clock = subprocess.check_output, time.monotonic

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
            proc = self.real_popen(argv, *args, **kwargs)
            if "clone" in argv and (self.mode == "clone_cancel" or self.mode == "clone_deadline"):
                wait = proc.wait
                def after_clone(*args, **kwargs):
                    result = wait(*args, **kwargs)
                    if result == 0:
                        if self.mode == "clone_cancel": self.runtime.container_cancel.set()
                        if self.mode == "clone_deadline": self.offset = 10
                    return result
                # The product intentionally never polls/reaps preparation
                # leaders before group shutdown. Inject at its final wait.
                proc.wait = after_clone
            return proc
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
                            ("harness.factory_container.source_check", fixtures.local_source_check),
                            ("harness.factory_container.inspect_image", lambda *a, **kw: IMAGE),
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
        # The clone's final wait advances offset past this original deadline.
        # Unlike target-stage tests, preparation must exhaust the whole budget.
        started = self.double.clock()
        self.double.clock = lambda: started
        with self.double.hooks(): result = self.gate()
        self.assertEqual(result["status"], "TIMEOUT")
        self.assertEqual(self.double.calls, [])
        self.assertFalse(self.double.ready.is_set())
        self.assert_stopped_cleanup(result)

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

    def assert_stopped_cleanup(self, result):
        for key in ("cleanup_confirmed", "preparation_cleanup_confirmed",
                    "local_clients_stop_confirmed", "temporary_directory_cleanup_confirmed"):
            self.assertTrue(result[key], result)
        self.assertEqual(result["local_clients_stop_status"], "CONFIRMED", result)
        self.assertTrue(result["preparation_clients"], result)
        for client in result["preparation_clients"]:
            self.assertTrue(client["confirmed"] and client["leader_reaped"], client)
        self.assertFalse(Path(result["temporary_directory_identity"]["path"]).exists())
        self.assertIsNone(self.runtime.current_process)
        self.assertIsNone(self.runtime._preparation_client)
        self.assertIsNone(self.runtime._active_execution)
        self.assertFalse(self.double.resources)

    def blocked_client(self, phase, cancel):
        self.double.mode = phase + "_blocked"
        results, errors, target = [], [], {}
        clock = self.double.clock
        started = clock()
        if not cancel:
            # Isolate target-client timing from real Git preparation latency.
            # clone_deadline above separately tests exhaustion before dispatch.
            self.double.clock = lambda: started
        consume = factory_container.consume_output
        finish = self.runtime._finish_owned_client

        def consume_target(proc, output, event, deadline, **kwargs):
            if self.double.ready.is_set() and proc is self.double.clients[-1]:
                client = self.runtime._preparation_client
                self.assertIs(self.runtime.current_process, proc)
                self.assertIs(client["process"], proc)
                self.assertIs(client["execution"], self.runtime._active_execution)
                self.assertEqual(client["identity"]["pid"], proc.pid)
                self.assertFalse(target, "target client consumed twice")
                target.update(process=proc, work_deadline=deadline)
                # Use most of the ORIGINAL 0.3s budget, retaining its cleanup
                # reserve. From here both work and cleanup use real elapsed time.
                self.assertAlmostEqual(deadline, started + 0.225)
                resumed = clock()
                self.double.offset = deadline - started - 0.02
                self.double.clock = lambda: started + clock() - resumed
            return consume(proc, output, event, deadline, **kwargs)

        def finish_target(client, deadline):
            if client["process"] is target.get("process"):
                target["cleanup_deadline"] = deadline
            return finish(client, deadline)

        def diagnostic():
            return (f"results={results!r}; errors={errors!r}; calls={self.double.calls!r}; "
                    f"ready={self.double.ready.is_set()}; worker_alive={worker.is_alive()}; "
                    f"current_process={self.runtime.current_process!r}; target={target!r}")

        def work():
            try: results.append(self.gate(5 if cancel else 0.3))
            except BaseException as error: errors.append("".join(traceback.format_exception(error)))
        worker = threading.Thread(target=work)
        with self.double.hooks() as hooks:
            if not cancel:
                hooks.enter_context(patch.object(factory_container, "consume_output", consume_target))
                hooks.enter_context(patch.object(self.runtime, "_finish_owned_client", finish_target))
            worker.start()
            try:
                self.assertTrue(self.double.ready.wait(2), diagnostic())
                client = self.double.clients[-1]
                if cancel:
                    # A stale identity has no authority over this preparation.
                    self.assertFalse(self.runtime.cancel(threading.Event()))
                    self.assertIsNone(client.poll())
                    self.assertTrue(self.runtime.cancel(self.runtime.container_cancel))
                worker.join(0.8)
                self.assertFalse(worker.is_alive(), diagnostic())
                # Check before fixture.close can kill or reap anything for us.
                self.assertEqual(client.returncode, -signal.SIGKILL, diagnostic())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(client.pid, os.WNOHANG)
                self.assertFalse(errors, diagnostic())
                self.assertEqual(len(results), 1, diagnostic())
                self.assert_stopped_cleanup(results[0])
            finally:
                self.double.close()
                worker.join(3)
        self.assertEqual(results[0]["status"], "CANCELLED" if cancel else "TIMEOUT")
        if not cancel:
            self.assertIs(target["process"], client)
            self.assertAlmostEqual(target["cleanup_deadline"], started + 0.3)
            self.assertGreater(target["cleanup_deadline"], target["work_deadline"])
        self.assertEqual([p for p, _ in self.double.calls if p != "rm"],
                         ["create"] if phase == "create" else ["create", "cp"])
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
        record = json.loads(Path(result["lifecycle_record"]).read_text())
        self.assertEqual(record["version"], 3)
        self.assertEqual(record["temporary_directory_identity"], result["temporary_directory_identity"])
        identity = record["temporary_directory_identity"]
        self.assertEqual(identity["binding"]["mission_id"], self.fx.spec["mission_id"])
        self.assertEqual(identity["binding"]["operation_id"], "gate")
        self.assertEqual(identity["path"], record["temporary_directory"])
        self.assertEqual(identity["mode"], "0o700")
        self.assertTrue(identity["nonce"])
        self.assertFalse(Path(identity["path"]).exists())


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
                record["target_sha256"] = "0" * 64
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

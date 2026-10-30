"""Publication data roots and one execution deadline; offline clients only."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

from harness.adapters import FootballPredictionAdapter
from harness.factory import git
from harness.factory_container import inspect_image
import harness.factory_container as container
from harness.factory_project import FootballPredictionContract
from harness.factory_remote import run as remote_run
from harness.factory_runtime import LocalRuntime
import test_factory_controller_gates as gates
from test_factory_container_lifecycle import DockerDouble
import test_factory_project_integration as project


def publication_body(fx, target):
    paths = ", ".join(target["files"])
    return f"""## Summary
Offline source-policy contract probe.
## Scope
| Field | Value |
| --- | --- |
| Task type | source-code |
| Workflow class | CRITICAL |
| Mission ID | feature |
| Mission scope contract | {fx.path} |
| Changed paths | {paths} |
| Authorized paths | {paths} |
| Excluded paths | none |
| Runtime behavior changed | yes |
| Business progress | Offline interface test |
## Documentation Impact
| Field | Value |
| --- | --- |
| Capability changed? | no |
| Milestone changed? | no |
| Canonical entrypoint changed? | no |
| Current blocker changed? | no |
| Data/model/authorization contract changed? | no |
| Repository structure/authority navigation changed? | no |
| Project vision / target-state changed? | no |
| Source-of-truth docs updated | no |
| Updated authoritative docs | none |
| If not updated, explicit reason | Synthetic source fixtures preserve project contracts and lifecycle boundaries. |
## Tests
Offline fixture only.
## Risk
No network, DB, model or production operations.
## Rollback
Revert the isolated fixture commit.
## Strict Review Evidence
| Field | Value |
| --- | --- |
| Version | 1 |
| Task type | CRITICAL |
| Provider | codex-cli, claude-code-deepseek |
| Reviewed full SHA | {target['head']} |
| Result | PASS |
| Timestamp | 2026-10-28T00:00:00Z |
"""


class PublicationDataRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project.CanonicalRuntimeIntegrationTests.setUpClass()
        cls.addClassCleanup(project.CanonicalRuntimeIntegrationTests.doClassCleanups)
        cls.snapshot = project.CanonicalRuntimeIntegrationTests.snapshot
        source = Path(os.environ.get("FOOTBALLPREDICTION_CONTRACT_REPO",
            str(Path(project.__file__).resolve().parents[2] / "FootballPrediction")))
        # A same-named real runtime file, deliberately not a governance module.
        cls.existing = "src/api/health.py"
        value = subprocess.check_output(["git", "-C", str(source), "show", f"{project.PROJECT_BASE}:{cls.existing}"])
        path = cls.snapshot / cls.existing
        path.parent.mkdir(parents=True)
        path.write_bytes(value)
        cls.rules = {p.relative_to(cls.snapshot).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in (cls.snapshot / "scripts").rglob("*.py")}

    def setUp(self):
        self.fx = project.CanonicalRuntimeIntegrationTests("test_pr_body_uses_original_trusted_preflight")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def candidate(self, path, content, *, later_edit=False):
        self.fx.scope["authorized_paths"].append(path)
        spec, cwd, target = self.fx.candidate()
        local = cwd / path
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(content)
        target = self.fx.f.checkpoint(spec, cwd)
        if later_edit:
            local.write_text(content + "\n# Later edit must not hide the earlier import.\n")
            target = self.fx.f.checkpoint(spec, cwd)
        return spec, cwd, target

    def publish(self, spec, cwd, target, *, rejected):
        remote = Mock(adapter=FootballPredictionAdapter())
        remote.publish.return_value = {"status": "PASS", "fixture": True}
        with patch("harness.factory_remote.Remote", return_value=remote):
            if rejected:
                with self.assertRaisesRegex(ValueError, "Archive runtime import detected"):
                    remote_run("publish", gates.DELIVERY, spec, cwd, target, publication_body(self.fx, target),
                               self.fx.root / "publication.raw", 5)
                remote.publish.assert_not_called()
                remote.command.assert_not_called()
                remote.api.assert_not_called()
            else:
                self.assertEqual(remote_run("publish", gates.DELIVERY, spec, cwd, target,
                    publication_body(self.fx, target), self.fx.root / "publication.raw", 5)["status"], "PASS")
                remote.publish.assert_called_once()
        self.assertEqual(self.fx.starts, [], "no provider may be called")
        self.assertEqual(self.rules, {p.relative_to(self.snapshot).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in (self.snapshot / "scripts").rglob("*.py")})

    def test_new_runtime_archive_reference_rejected_before_publication(self):
        self.assertFalse((self.snapshot / "src/probe.py").exists())
        self.publish(*self.candidate("src/probe.py", "import archive_vault_2026.probe\n"), rejected=True)

    def test_same_named_existing_file_checks_candidate_content(self):
        original = (self.snapshot / self.existing).read_text()
        spec, cwd, target = self.candidate(self.existing, original + "\nimport archive_vault_2026.probe\n")
        self.assertNotEqual((cwd / self.existing).read_text(), original)
        self.publish(spec, cwd, target, rejected=True)

    def test_legal_candidate_passes_original_rules(self):
        original = (self.snapshot / self.existing).read_text()
        self.publish(*self.candidate(self.existing, original + "\n# Legal offline candidate edit.\n"), rejected=False)

    def test_earlier_import_remains_in_full_base_comparison(self):
        self.publish(*self.candidate("src/probe.py", "import archive_vault_2026.probe\n", later_edit=True), rejected=True)

    def test_new_script_lifecycle_header_is_read_from_candidate(self):
        spec, cwd, target = self.candidate("scripts/ops/probe.py", "# Owner: offline fixture\nprint('local only')\n")
        self.assertTrue(FootballPredictionContract().validate_pr_body(
            spec, cwd, target, publication_body(self.fx, target)).is_file())
        (cwd / "scripts/ops/probe.py").write_text("print('local only')\n")
        target = self.fx.f.checkpoint(spec, cwd)
        with self.assertRaisesRegex(ValueError, "Script lifecycle missing"):
            FootballPredictionContract().validate_pr_body(spec, cwd, target, publication_body(self.fx, target))
        self.assertEqual(self.fx.starts, [])

    def test_disposable_proof_marker_is_read_from_candidate_revision(self):
        path = "tests/integration/canonical_inventory/disposable_postgres.test.js"
        spec, cwd, target = self.candidate(path,
            '// M3_CANONICAL_DISPOSABLE_DB_WRITE_PROOF_V1\nconst sql = "DELETE FROM cmh_fixture";\n')
        body = publication_body(self.fx, target)
        self.assertTrue(FootballPredictionContract().validate_pr_body(spec, cwd, target, body).is_file())
        (cwd / path).write_text('const sql = "DELETE FROM cmh_fixture";\n')
        target = self.fx.f.checkpoint(spec, cwd)
        with self.assertRaisesRegex(ValueError, "new dangerous keyword"):
            FootballPredictionContract().validate_pr_body(spec, cwd, target, publication_body(self.fx, target))
        self.assertEqual(self.fx.starts, [])

    def test_source_query_runs_real_verifiers_and_rejects_changed_identity(self):
        spec, cwd, target = self.fx.candidate()
        request = self.fx.root / "source-query.json"
        request.write_text(json.dumps({"spec": spec, "cwd": str(cwd), "workspace": str(cwd), "target": target}))
        runtime = LocalRuntime()
        execution = runtime.begin_execution(spec["mission_id"])
        self.addCleanup(runtime.end_execution, execution)
        with (self.fx.root / "source-query.raw").open("wb") as log:
            before = container.source_check(runtime, request, "candidate", log, execution, time.monotonic() + 10)
            after = container.source_check(runtime, request, "final", log, execution, time.monotonic() + 10)
            self.assertEqual(before["source"], after["source"])
            self.assertFalse(after["snapshot_dirty"])
            (cwd / "score.py").write_text("unexpected candidate mutation\n")
            with self.assertRaises(ValueError):
                container.source_check(runtime, request, "candidate", log, execution, time.monotonic() + 10)
        self.assertIsNone(runtime.current_process)
        self.assertEqual(self.fx.starts, [])


class InspectionDouble(DockerDouble):
    def __init__(self, fixture, runtime, delays):
        super().__init__(fixture, runtime)
        self.delays, self.inspections = delays, []
        self.copy_delay = 0
        self.warning = b""

    def image_client(self, argv, **kwargs):
        self.inspections.append({"image": argv[-1], "cancelled": self.runtime.container_cancel.is_set(),
                                 "started": self.clock()})
        delay = self.delays[min(len(self.inspections) - 1, len(self.delays) - 1)]
        client = self.real_popen([sys.executable, "-B", "-c",
            f"import sys,time; time.sleep({delay!r}); sys.stderr.buffer.write({self.warning!r}); print({gates.IMAGE!r})"],
            stdout=subprocess.PIPE, stderr=kwargs.get("stderr", subprocess.STDOUT), start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.clients.append(client)
        self.ready.set()
        return client

    def popen(self, argv, *args, **kwargs):
        if argv[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return self.image_client(argv, **kwargs)
        if argv[:2] == ["/usr/bin/docker", "cp"] and self.copy_delay:
            self.calls.append(("cp", argv))
            client = self.real_popen([sys.executable, "-B", "-c", f"import time; time.sleep({self.copy_delay!r})"],
                                     **kwargs)
            self.clients.append(client)
            return client
        return super().popen(argv, *args, **kwargs)

    def output(self, argv, *args, **kwargs):
        # Exercise the old synchronous inspector too, for before-fix evidence.
        if argv[:3] == ["/usr/bin/docker", "image", "inspect"]:
            client = self.image_client(argv)
            try:
                return client.communicate(timeout=kwargs["timeout"])[0]
            finally:
                if client.poll() is None:
                    client.kill()
                    client.wait(timeout=2)
                client.stdout.close()
        return super().output(argv, *args, **kwargs)

    def hooks(self):
        stack = ExitStack()
        stack.enter_context(super().hooks())
        stack.enter_context(patch("harness.factory_container.inspect_image", side_effect=inspect_image))
        return stack


class InitialInspectionTests(unittest.TestCase):
    def setUp(self):
        self.fx = gates.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.runtime = LocalRuntime()
        old = self.runtime.begin_execution("old")
        self.runtime.end_execution(old)
        self.old_execution = old
        self.double = InspectionDouble(self.fx, self.runtime, [0.65, 0.65])
        self.addCleanup(self.double.close)

    def gate(self, timeout):
        return self.runtime.container_gate(gates.CONTAINER, self.fx.spec, self.fx.cwd, self.fx.target,
            ["make", "verify-targeted"], self.fx.root / "inspection.raw", timeout)

    def assert_reaped(self):
        self.assertTrue(all(p.poll() is not None for p in self.double.clients))
        self.assertIsNone(self.runtime.current_process)
        self.assertFalse(self.double.resources)

    def test_two_slow_inspections_share_total_deadline_and_elapsed(self):
        started = time.monotonic()
        with self.double.hooks(): result = self.gate(1)
        elapsed = time.monotonic() - started
        self.assertEqual(result["status"], "TIMEOUT", result)
        self.assertLess(elapsed, 1.3)
        self.assertAlmostEqual(result["elapsed_seconds"], elapsed, delta=0.08)
        self.assertEqual(len(self.double.inspections), 2)
        self.assertFalse(self.double.calls, "no preparation or validation after image timeout")
        self.assert_reaped()

    def test_cancel_first_inspection_reaps_client_and_skips_second(self):
        results, errors = [], []
        def work():
            try: results.append(self.gate(4))
            except BaseException as error: errors.append(error)
        worker = threading.Thread(target=work)
        with self.double.hooks():
            worker.start()
            try:
                self.assertTrue(self.double.ready.wait(2))
                client = self.double.clients[0]
                self.assertFalse(self.runtime.cancel(self.old_execution))
                self.assertIsNone(client.poll(), "old execution cannot kill this client")
                self.assertIs(self.runtime.current_process, client, "initial client must be tracked")
                self.assertTrue(self.runtime.cancel(self.runtime.container_cancel))
                worker.join(0.4)
                self.assertFalse(worker.is_alive(), "initial check ignored cancellation")
                self.assertIsNotNone(client.poll())
            finally:
                self.double.close()
                worker.join(3)
        self.assertFalse(errors, errors)
        self.assertEqual(results[0]["status"], "CANCELLED")
        self.assertEqual(len(self.double.inspections), 1)
        self.assertFalse(self.double.calls)
        self.assert_reaped()

    def test_pre_cancelled_execution_starts_no_inspection(self):
        execution = self.runtime.begin_execution(self.fx.spec["mission_id"])
        self.assertTrue(self.runtime.cancel(execution))
        try:
            with self.double.hooks(): result = self.gate(3)
            self.assertEqual(result["status"], "CANCELLED")
            self.assertFalse(self.double.inspections)
            self.assertFalse(self.double.calls)
            self.assert_reaped()
        finally:
            self.runtime.end_execution(execution)

    def test_inspection_and_copy_share_remaining_time_and_cleanup(self):
        self.double.delays, self.double.copy_delay = [0.3, 0.3], 0.6
        with self.double.hooks(): result = self.gate(1)
        self.assertEqual(result["status"], "TIMEOUT", result)
        self.assertNotIn("run", [p for p, _ in self.double.calls])
        self.assertTrue(result["dependencies_cleanup_confirmed"])
        self.assert_reaped()

    def test_normal_images_and_validation_remain_usable(self):
        self.double.delays = [0.03, 0.03]
        with self.double.hooks(): result = self.gate(5)
        self.assertEqual(result["status"], "PASS", result)
        self.assertGreaterEqual(result["elapsed_seconds"], 0.06)
        self.assertEqual(len(self.double.inspections), 2)
        self.assertEqual([p for p, _ in self.double.calls if p != "rm"], ["create", "cp", "run"])
        self.assertTrue(result["source_unchanged"])
        self.assert_reaped()

    def test_image_diagnostics_do_not_change_stdout_identity(self):
        self.double.delays, self.double.warning = [0.01, 0.01], b"synthetic diagnostic\n"
        with self.double.hooks(): result = self.gate(5)
        self.assertEqual(result["status"], "PASS", result)
        self.assert_reaped()


class RemainingPreparationTests(unittest.TestCase):
    def setUp(self):
        self.fx = gates.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.runtime = LocalRuntime()
        self.double = DockerDouble(self.fx, self.runtime)
        self.addCleanup(self.double.close)

    def stopped_source_query(self, phase, cancel):
        clients, results, errors = [], [], []
        ready = threading.Event()
        original = self.double.popen
        def launch(argv, *args, **kwargs):
            if argv[-1] == phase and "-c" in argv and "from harness.factory_container import binding" in argv[4]:
                proc = self.double.real_popen([sys.executable, "-B", "-c", "import time; time.sleep(30)"], **kwargs)
                self.double.clients.append(proc)
                clients.append(proc)
                ready.set()
                return proc
            return original(argv, *args, **kwargs)
        self.double.popen = launch
        # Retain a reference before patching the gate's query function.
        real_query = container.source_check
        def selected_query(runtime, request, stage, log, event, deadline):
            if stage == phase:
                return real_query(runtime, request, stage, log, event, deadline)
            return gates.local_source_check(runtime, request, stage, log, event, deadline)
        def work():
            try:
                results.append(self.runtime.container_gate(gates.CONTAINER, self.fx.spec, self.fx.cwd,
                    self.fx.target, ["make", "verify-targeted"], self.fx.root / (phase + ".raw"), 4 if cancel else 0.8))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=work)
        with self.double.hooks(), patch("harness.factory_container.source_check", side_effect=selected_query):
            worker.start()
            try:
                self.assertTrue(ready.wait(2))
                if cancel:
                    self.assertIs(self.runtime.current_process, clients[0])
                    self.assertTrue(self.runtime.cancel(self.runtime.container_cancel))
                worker.join(0.5 if cancel else 1.2)
                self.assertFalse(worker.is_alive(), "source/Git/policy query ignored execution boundary")
                self.assertIsNotNone(clients[0].poll())
            finally:
                self.double.close()
                worker.join(3)
        self.assertFalse(errors, errors)
        self.assertEqual(results[0]["status"], "CANCELLED" if cancel else "TIMEOUT")
        self.assertFalse(results[0]["source_unchanged"])
        self.assertFalse(self.double.resources)
        self.assertIsNone(self.runtime.current_process)
        if phase != "final": self.assertNotIn("run", [p for p, _ in self.double.calls])
        else: self.assertEqual(results[0]["exit_code"], 0, "retain the already exited validation result")

    def test_candidate_query_cancel(self): self.stopped_source_query("candidate", True)
    def test_candidate_query_deadline(self): self.stopped_source_query("candidate", False)
    def test_snapshot_query_cancel(self): self.stopped_source_query("snapshot", True)
    def test_snapshot_query_deadline(self): self.stopped_source_query("snapshot", False)
    def test_final_query_cancel(self): self.stopped_source_query("final", True)
    def test_final_query_deadline(self): self.stopped_source_query("final", False)


class ServiceDouble(InspectionDouble):
    def __init__(self, fixture, runtime, blocked=None):
        super().__init__(fixture, runtime, [0.01, 0.01])
        self.blocked, self.service_ready, self.blocked_clients = blocked, threading.Event(), []
        self.service_warning = b""

    def popen(self, argv, *args, **kwargs):
        phase = None
        if argv[0] == "/usr/bin/docker":
            if "--detach" in argv: phase = "start"
            elif argv[1] == "inspect": phase = "inspect"
            elif argv[1] == "exec": phase = "health"
        if phase is None:
            return super().popen(argv, *args, **kwargs)
        self.calls.append(("postgres-" + phase, argv))
        if phase == "start":
            name = argv[argv.index("--name") + 1]
            self.resources[name] = dict(x.split("=", 1) for i, x in enumerate(argv) if i and argv[i - 1] == "--label")
        out = (b'{"network":"none","ports":{},"mounts":[],"tmpfs":{}}' if phase == "inspect"
               else b"1\n" if phase == "health" else b"")
        script = ("import time; time.sleep(30)" if phase == self.blocked else
                  f"import sys; sys.stderr.buffer.write({self.service_warning!r}); sys.stdout.buffer.write({out!r})")
        proc = self.real_popen([sys.executable, "-B", "-c", script], **kwargs)
        self.clients.append(proc)
        if phase == self.blocked:
            self.blocked_clients.append(proc)
            self.service_ready.set()
        return proc

    def command(self, argv, *args, **kwargs):
        if argv[:2] == ["/usr/bin/docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.resources.get(argv[-1], {})).encode(), b"")
        if argv[:2] == ["/usr/bin/docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, self.output(argv), b"")
        if argv[:2] == ["/usr/bin/docker", "logs"]:
            return subprocess.CompletedProcess(argv, 0, b"offline service log", b"")
        return super().command(argv, *args, **kwargs)


class ServiceClientBoundaryTests(unittest.TestCase):
    def test_cleanup_diagnostic_loss_cleans_owned_service_but_cannot_pass_the_gate(self):
        from test_factory_test_service import BrokenDiagnosticLog
        from harness.factory_test_service import ProjectPostgres
        fx = gates.ControllerGatesTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        runtime = LocalRuntime()
        double = ServiceDouble(fx, runtime)
        self.addCleanup(double.close)
        original_close = ProjectPostgres.close

        def close_with_failed_sink(service):
            # Only cleanup diagnostics lose their sink; actual command outcomes
            # and the final source check remain available to the Controller.
            service.log = BrokenDiagnosticLog()
            original_close(service)

        with double.hooks(), patch.object(ProjectPostgres, "close", close_with_failed_sink):
            result = runtime.container_gate(gates.CONTAINER, fx.spec, fx.cwd, fx.target,
                ["make", "verify-pr"], fx.root / "service-log-fault.raw", 5)
        self.assertFalse(double.resources)
        self.assertTrue(result["cleanup_confirmed"])
        self.assertTrue(result["services"]["postgres"]["cleanup_confirmed"])
        self.assertFalse(result["services"]["postgres"]["diagnostics_complete"])
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["source_unchanged"])
        self.assertEqual(result["status"], "BLOCKED_ENVIRONMENT", result)
        self.assertTrue(all(p.poll() is not None for p in double.clients))
        self.assertIsNone(runtime.current_process)

    def test_service_log_command_failure_is_recorded_and_cannot_pass_the_gate(self):
        fx = gates.ControllerGatesTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        runtime = LocalRuntime()
        double = ServiceDouble(fx, runtime)
        self.addCleanup(double.close)
        original_command = double.command
        def command(argv, *args, **kwargs):
            if argv[:2] == ["/usr/bin/docker", "logs"]:
                return subprocess.CompletedProcess(argv, 7, b"", b"synthetic log command failure")
            return original_command(argv, *args, **kwargs)
        double.command = command
        with double.hooks():
            result = runtime.container_gate(gates.CONTAINER, fx.spec, fx.cwd, fx.target,
                ["make", "verify-pr"], fx.root / "service-log-command-fault.raw", 5)
        self.assertFalse(double.resources)
        self.assertTrue(result["cleanup_confirmed"])
        service = result["services"]["postgres"]
        self.assertEqual(service["logs_exit_code"], 7)
        self.assertFalse(service["diagnostics_complete"])
        self.assertEqual(result["status"], "BLOCKED_ENVIRONMENT", result)

    def test_service_metadata_diagnostics_preserve_stdout_json(self):
        fx = gates.ControllerGatesTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        runtime = LocalRuntime()
        double = ServiceDouble(fx, runtime)
        double.service_warning = b"synthetic diagnostic\n"
        self.addCleanup(double.close)
        with double.hooks():
            result = runtime.container_gate(gates.CONTAINER, fx.spec, fx.cwd, fx.target,
                ["make", "verify-pr"], fx.root / "service.raw", 5)
        self.assertEqual(result["status"], "PASS", result)
        self.assertIn(b"synthetic diagnostic", (fx.root / "service.raw").read_bytes())
        self.assertFalse(double.resources)
        self.assertTrue(all(p.poll() is not None for p in double.clients))
        self.assertIsNone(runtime.current_process)

    def stopped_service(self, phase, cancel):
        fx = gates.ControllerGatesTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        runtime = LocalRuntime()
        old = runtime.begin_execution("old")
        runtime.end_execution(old)
        double = ServiceDouble(fx, runtime, phase)
        self.addCleanup(double.close)
        results, errors = [], []
        def work():
            try:
                results.append(runtime.container_gate(gates.CONTAINER, fx.spec, fx.cwd, fx.target,
                    ["make", "verify-pr"], fx.root / "service.raw", 4 if cancel else 0.8))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=work)
        with double.hooks():
            worker.start()
            try:
                self.assertTrue(double.service_ready.wait(2))
                client = double.blocked_clients[0]
                if cancel:
                    self.assertFalse(runtime.cancel(old))
                    self.assertIsNone(client.poll())
                    self.assertIs(runtime.current_process, client)
                    self.assertTrue(runtime.cancel(runtime.container_cancel))
                worker.join(0.5 if cancel else 1.2)
                self.assertFalse(worker.is_alive())
                self.assertIsNotNone(client.poll())
            finally:
                double.close()
                worker.join(3)
        self.assertFalse(errors, errors)
        self.assertEqual(results[0]["status"], "CANCELLED" if cancel else "TIMEOUT")
        self.assertTrue(results[0]["services"]["postgres"]["cleanup_confirmed"])
        self.assertFalse(double.resources)
        self.assertIsNone(runtime.current_process)
        self.assertTrue(all(p.poll() is not None for p in double.clients))
        self.assertNotIn("run", [p for p, _ in double.calls], "validation cannot start after service preparation stops")
        stages = [p.removeprefix("postgres-") for p, _ in double.calls if p.startswith("postgres-")]
        self.assertEqual(stages, ["start", "inspect", "health"][:["start", "inspect", "health"].index(phase) + 1])

    def test_service_start_cancel(self): self.stopped_service("start", True)
    def test_service_inspection_cancel(self): self.stopped_service("inspect", True)
    def test_service_health_cancel(self): self.stopped_service("health", True)
    def test_service_start_deadline(self): self.stopped_service("start", False)
    def test_service_inspection_deadline(self): self.stopped_service("inspect", False)
    def test_service_health_deadline(self): self.stopped_service("health", False)

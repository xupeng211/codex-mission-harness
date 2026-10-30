"""离线回归：真实本地子进程、合成 Git/CI/发布替身，不运行 Docker 或远端。"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from harness.factory import READY, FactoryBlocked, validate_config, validate_mission
from harness.factory_fixture import fixture_config
from harness.factory_runtime import LocalRuntime, RuntimeFailure
from harness.factory_test_service import ExecutionStopped
import test_factory_controller_gates as fixtures
from test_factory_container_lifecycle import DockerDouble


class SourcePreparationTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.runtime = LocalRuntime()
        self.old_execution = self.runtime.begin_execution("previous")
        self.runtime.end_execution(self.old_execution)
        self.double = DockerDouble(self.fx, self.runtime)
        self.addCleanup(self.double.close)

    def stopped_git(self, phase, cancel):
        ready = threading.Event()
        clients, results, errors = [], [], []
        original_popen = self.double.popen
        def launch(argv, *args, **kwargs):
            if Path(argv[0]).name == "git" and phase in argv:
                proc = self.double.real_popen([sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                    **{**kwargs, "start_new_session": True})
                clients.append(proc)
                self.double.clients.append(proc)
                ready.set()
                return proc
            return original_popen(argv, *args, **kwargs)
        self.double.popen = launch
        def work():
            try:
                results.append(self.runtime.container_gate(fixtures.CONTAINER, self.fx.spec, self.fx.cwd,
                    self.fx.target, ["make", "verify-targeted"], self.fx.root / "git.raw", 3 if cancel else 1))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=work)
        with self.double.hooks():
            worker.start()
            try:
                self.assertTrue(ready.wait(2), "未到达目标 Git 准备步骤")
                client = clients[0]
                if cancel:
                    self.assertFalse(self.runtime.cancel(self.old_execution))
                    self.assertIsNone(client.poll(), "旧执行身份终止了新任务")
                    self.assertTrue(self.runtime.cancel(self.runtime.container_cancel))
                worker.join(0.8 if cancel else 1.5)
                self.assertFalse(worker.is_alive(), "Git 准备没有响应取消或剩余时限")
                self.assertIsNotNone(client.poll(), "必须结束并回收真实客户端")
            finally:
                self.double.close()
                worker.join(3)
        self.assertFalse(errors, errors)
        self.assertEqual(results[0]["status"], "CANCELLED" if cancel else "TIMEOUT")
        self.assertTrue(results[0]["temporary_directory_cleanup_confirmed"])
        self.assertFalse(self.double.calls, "Git 准备未完成却派发了 Docker 工作")
        self.assertIsNone(self.runtime.current_process)
        self.assertIsNone(self.runtime._active_execution)

    def test_clone_cancel_stops_client_without_later_dispatch(self): self.stopped_git("clone", True)
    def test_checkout_cancel_stops_client_without_later_dispatch(self): self.stopped_git("checkout", True)
    def test_clone_uses_remaining_deadline(self): self.stopped_git("clone", False)
    def test_checkout_uses_remaining_deadline(self): self.stopped_git("checkout", False)

    def test_normal_source_preparation_still_runs_validation_and_cleans(self):
        with self.double.hooks():
            result = self.runtime.container_gate(fixtures.CONTAINER, self.fx.spec, self.fx.cwd, self.fx.target,
                ["make", "verify-targeted"], self.fx.root / "normal.raw", 5)
        self.assertEqual(result["status"], "PASS", result)
        self.assertTrue(result["source_unchanged"])
        self.assertTrue(result["temporary_directory_cleanup_confirmed"])
        self.assertFalse(self.double.resources)


WORKER = r'''
import json,sys,time
from types import SimpleNamespace
import harness.factory_remote as remote_module
from harness.adapters import GateResult
data=json.load(sys.stdin)
mode=sys.argv[1]
if mode == 'ignore_cancel':
 import signal
 from pathlib import Path
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 Path(data['cwd'],'worker.ready').write_text('synthetic client ready')
 time.sleep(30)
if mode == 'exit': sys.exit(7)
if mode == 'invalid':
 print('not a JSON observation',flush=True)
 sys.exit(0)
if mode == 'delayed_pass':
 from pathlib import Path
 Path(data['cwd'],'worker.ready').write_text('offline observation waiting')
 end=time.monotonic()+5
 while not Path(data['cwd'],'worker.release').exists() and time.monotonic()<end: time.sleep(0.005)
 if not Path(data['cwd'],'worker.release').exists(): sys.exit(8)
if mode == 'partial':
 print(json.dumps({'status':'TIMEOUT'}),flush=True)
if mode in {'hang','partial'}: time.sleep(30)
OriginalRemote=remote_module.Remote
class Pending(OriginalRemote):
 def __init__(self,*args,**kwargs):
  super().__init__(*args,adapter=SimpleNamespace(
   _trusted_subprocess_environment=lambda **kw:{},
   ci=lambda *a,**kw:GateResult('PASS' if mode in {'pass','delayed_pass'} else 'FAIL' if mode == 'fail' else 'PENDING','offline queued CI')),**kwargs)
 def observe(self,policy,spec,target,body):
  if time.monotonic() >= self.deadline: raise TimeoutError('no observation after worker deadline')
  return {'status':'PASS','target':target,'pr_number':7,'pr_repo':'fixture/only','pr_base_sha':target['base']}
 def ci(self,*args,**kwargs):
  result=super().ci(*args,**kwargs)
  return {**result,'worker_deadline_used':self.deadline}
remote_module.Remote=Pending
remote_module.verify_target=lambda *args:None
remote_module.FootballPredictionContract=lambda *args:SimpleNamespace(validate_pr_body=lambda *a:None)
print(json.dumps(remote_module.run(**data)),flush=True)
'''


class RemoteWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cmh-worker-regression-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = LocalRuntime()
        self.clients = []
        self.real_popen = subprocess.Popen
        self.timeout = validate_config({**fixture_config(), "timeout_seconds": 1})["timeout_seconds"]
        self.addCleanup(self.cleanup_clients)

    def cleanup_clients(self):
        for proc in self.clients:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=2)
            for stream in (proc.stdin, proc.stdout):
                if stream is not None and not stream.closed: stream.close()

    def hooks(self, mode):
        def launch(argv, **kwargs):
            proc = self.real_popen([sys.executable, "-B", "-c", WORKER, mode], **kwargs)
            self.clients.append(proc)
            return proc
        stack = ExitStack()
        stack.enter_context(patch("harness.factory_runtime.subprocess.Popen", side_effect=launch))
        stack.enter_context(patch("harness.adapters.FootballPredictionAdapter._trusted_subprocess_environment",
                                  return_value={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}))
        return stack

    def invoke(self, transcript=None, *, mission="feature"):
        return self.runtime.project_remote("ci", {}, {"mission_id": mission}, self.root, {"head": "a" * 40, "base": "b" * 40},
            "", transcript or self.root / "ci.raw", self.timeout)

    def assert_reaped(self):
        self.assertTrue(self.clients)
        self.assertTrue(all(p.poll() is not None for p in self.clients))
        self.assertIsNone(self.runtime.current_process)

    def test_pending_worker_returns_confirmed_timeout_inside_original_total(self):
        started = time.monotonic()
        result, error = None, None
        with self.hooks("pending"):
            try: result = self.invoke()
            except Exception as exc: error = exc
        elapsed = time.monotonic() - started
        self.assertIsNone(error, repr(error))
        self.assertEqual(result["status"], "TIMEOUT")
        self.assertLess(result["worker_deadline_used"], started + self.timeout - 0.1)
        self.assertLess(elapsed, self.timeout + 0.15, "没有延长原总时限")
        self.assert_reaped()

    def test_completed_worker_result_is_preserved(self):
        with self.hooks("pass"): result = self.invoke()
        self.assertEqual(result["status"], "PASS")
        self.assert_reaped()

    def test_abnormal_worker_exit_is_an_error_not_a_timeout_result(self):
        with self.hooks("exit"), self.assertRaises(RuntimeFailure): self.invoke()
        self.assert_reaped()

    def test_parent_cutoff_does_not_fabricate_timeout_even_with_partial_json(self):
        for mode in ("hang", "partial"):
            with self.subTest(mode=mode):
                started = time.monotonic()
                with self.hooks(mode), self.assertRaises(subprocess.TimeoutExpired):
                    self.invoke(self.root / (mode + ".raw"))
                self.assertLess(time.monotonic() - started, self.timeout + 0.15)
                self.assert_reaped()

    def test_cancellation_is_distinct_and_reaps_only_current_execution(self):
        previous = self.runtime.begin_execution("previous")
        self.runtime.end_execution(previous)
        current = self.runtime.begin_execution("current")
        errors, cancelled_at = [], []
        def cancel():
            try:
                end = time.monotonic() + 2
                while time.monotonic() < end and not self.clients: time.sleep(0.005)
                proc = self.clients[-1]
                while time.monotonic() < end and not (self.root / "worker.ready").exists(): time.sleep(0.005)
                self.assertTrue((self.root / "worker.ready").exists())
                self.assertFalse(self.runtime.cancel(previous))
                self.assertIsNone(proc.poll())
                cancelled_at.append(time.monotonic())
                self.assertTrue(self.runtime.cancel(current))
            except BaseException as exc: errors.append(exc)
        watcher = threading.Thread(target=cancel)
        caught = None
        with self.hooks("ignore_cancel"):
            watcher.start()
            try:
                try: self.invoke(mission="current")
                except Exception as exc: caught = exc
            finally:
                watcher.join(3)
                self.runtime.end_execution(current)
        self.assertFalse(errors, errors)
        self.assertIsInstance(caught, ExecutionStopped)
        self.assertEqual(caught.outcome, "CANCELLED")
        self.assertLess(time.monotonic() - cancelled_at[0], 0.5, "忽略 TERM 的客户端也应及时结束")
        self.assert_reaped()

    def test_already_cancelled_execution_starts_no_worker(self):
        current = self.runtime.begin_execution("cancelled")
        self.assertTrue(self.runtime.cancel(current))
        try:
            with self.hooks("hang"), self.assertRaises(ExecutionStopped) as stopped:
                self.invoke(mission="cancelled")
            self.assertEqual(stopped.exception.outcome, "CANCELLED")
            self.assertFalse(self.clients)
            self.assertIs(self.runtime._active_execution, current)
            self.assertTrue(current.is_set())
        finally:
            self.runtime.end_execution(current)

    def test_forced_or_failed_workers_leave_operation_unknown(self):
        fx = fixtures.FactoryLiveProtocolTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        for mode in ("exit", "partial"):
            with self.subTest(mode=mode), self.hooks(mode), self.assertRaises(FactoryBlocked) as blocked:
                fx.f.operation("feature", mode, "project_ci", "local", {}, {}, False, self.invoke)
            self.assertEqual(blocked.exception.status, "UNKNOWN")
            row = fx.f.db.execute("SELECT status,result FROM operations WHERE key=?", (mode,)).fetchone()
            self.assertEqual(row["status"], "UNKNOWN")
            self.assertNotIn("status", json.loads(row["result"]))
            self.assert_reaped()

    def test_cancelled_and_ended_unrelated_task_does_not_block_a_new_observation(self):
        previous = self.runtime.begin_execution("unrelated")
        self.assertTrue(self.runtime.cancel(previous))
        self.runtime.end_execution(previous)
        with self.hooks("pass"): result = self.invoke()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(self.clients), 1, "必须启动并完成新观察，不能返回缓存")
        self.assertTrue(previous.is_set())
        self.assertIsNot(self.runtime.container_cancel, previous)
        self.assertIsNone(self.runtime._active_execution)
        self.assertIsNone(self.runtime._active_mission)
        self.assertIsNone(self.runtime._execution_thread)
        self.assert_reaped()

    def test_standalone_query_releases_its_identity_on_result_or_exception(self):
        for mode, error in (("pass", None), ("exit", RuntimeFailure), ("invalid", json.JSONDecodeError)):
            with self.subTest(mode=mode), self.hooks(mode):
                if error is None: self.assertEqual(self.invoke(self.root / (mode + ".raw"))["status"], "PASS")
                else:
                    with self.assertRaises(error): self.invoke(self.root / (mode + ".raw"))
            self.assertIsNone(self.runtime._active_execution)
            self.assertIsNone(self.runtime._active_mission)
            self.assertIsNone(self.runtime._execution_thread)
            self.assert_reaped()

    def test_standalone_launch_error_releases_its_identity(self):
        with self.hooks("pass"), patch("harness.factory_runtime.subprocess.Popen", side_effect=OSError("offline launch failed")):
            with self.assertRaises(OSError): self.invoke()
        self.assertFalse(self.clients)
        self.assertIsNone(self.runtime._active_execution)
        self.assertIsNone(self.runtime._active_mission)
        self.assertIsNone(self.runtime._execution_thread)
        self.assertIsNone(self.runtime.current_process)

    def test_failed_observation_is_not_changed_into_pass(self):
        with self.hooks("fail"): result = self.invoke()
        self.assertEqual(result["status"], "FAIL")
        self.assertIsNone(self.runtime._active_execution)
        self.assert_reaped()

    def test_successful_active_call_keeps_its_owners_identity(self):
        current = self.runtime.begin_execution("feature")
        try:
            with self.hooks("pass"): result = self.invoke()
            self.assertEqual(result["status"], "PASS")
            self.assertIs(self.runtime._active_execution, current)
            self.assertIs(self.runtime.container_cancel, current)
            self.assertFalse(current.is_set())
            self.assert_reaped()
        finally:
            self.runtime.end_execution(current)

    def test_late_old_cancel_and_end_cannot_stop_a_standalone_observation(self):
        old = self.runtime.begin_execution("old")
        self.assertTrue(self.runtime.cancel(old))
        self.runtime.end_execution(old)
        self.timeout = 3
        results, errors = [], []
        def observe():
            try: results.append(self.invoke())
            except BaseException as error: errors.append(error)
        worker = threading.Thread(target=observe)
        with self.hooks("delayed_pass"):
            worker.start()
            try:
                end = time.monotonic() + 2
                while time.monotonic() < end and not (self.root / "worker.ready").exists(): time.sleep(0.005)
                self.assertTrue((self.root / "worker.ready").exists(), errors)
                current = self.runtime._active_execution
                self.assertIsNotNone(current)
                self.assertIsNot(current, old)
                self.assertFalse(self.runtime.cancel(old))
                self.runtime.end_execution(old)
                self.assertIs(self.runtime._active_execution, current)
                self.assertFalse(current.is_set())
                self.assertIsNone(self.clients[0].poll())
                (self.root / "worker.release").touch()
                worker.join(2)
                self.assertFalse(worker.is_alive())
            finally:
                self.cleanup_clients()
                worker.join(3)
        self.assertFalse(errors, errors)
        self.assertEqual(results[0]["status"], "PASS")
        self.assertIsNone(self.runtime._active_execution)
        self.assert_reaped()

    def test_other_active_mission_identity_and_cancellation_cannot_be_stolen(self):
        current = self.runtime.begin_execution("other")
        self.assertTrue(self.runtime.cancel(current))
        try:
            with self.hooks("pass"), self.assertRaisesRegex(RuntimeError, "different active execution"):
                self.invoke()
            self.assertFalse(self.clients)
            self.assertIs(self.runtime._active_execution, current)
            self.assertEqual(self.runtime._active_mission, "other")
            self.assertIs(self.runtime.container_cancel, current)
            self.assertTrue(current.is_set())
        finally:
            self.runtime.end_execution(current)

    def test_same_mission_on_another_thread_cannot_borrow_active_identity(self):
        current = self.runtime.begin_execution("feature")
        errors = []
        def observe():
            try: self.invoke()
            except BaseException as error: errors.append(error)
        worker = threading.Thread(target=observe)
        try:
            with self.hooks("pass"):
                worker.start()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], RuntimeError)
            self.assertIn("different active execution", str(errors[0]))
            self.assertFalse(self.clients)
            self.assertIs(self.runtime._active_execution, current)
            self.assertFalse(current.is_set())
        finally:
            self.cleanup_clients()
            worker.join(3)
            self.runtime.end_execution(current)


class ReportExecutionIsolationTests(unittest.TestCase):
    def test_report_observes_again_after_an_unrelated_cancelled_execution(self):
        # Factory, operation evidence and worker controller are real. Development,
        # reviews, container and GitHub authority remain explicit offline doubles.
        class Runtime(fixtures.LiveProtocolDouble, LocalRuntime):
            def __init__(self):
                fixtures.LiveProtocolDouble.__init__(self)
                LocalRuntime.__init__(self)
                self.real_controller = False

            def project_remote(self, *args, **kwargs):
                method = LocalRuntime.project_remote if self.real_controller else fixtures.LiveProtocolDouble.project_remote
                return method(self, *args, **kwargs)

        fx = fixtures.FactoryLiveProtocolTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        runtime = Runtime()
        fx.f.runtime = runtime
        ready = fx.f.run("feature")
        self.assertEqual(ready["DELIVERY_STATUS"], READY)
        observation = ready["CURRENT_REMOTE_VERIFICATION"]
        runtime.real_controller = True
        original_popen, starts = subprocess.Popen, []

        def local_observation(argv, *args, **kwargs):
            if argv != [sys.executable, "-m", "harness.factory_remote"]:
                return original_popen(argv, *args, **kwargs)
            starts.append(runtime._active_execution)
            code = "import json,sys; json.load(sys.stdin); print(" + repr(json.dumps(observation)) + ")"
            return original_popen([sys.executable, "-I", "-B", "-c", code], *args, **kwargs)

        with patch("harness.factory_runtime.subprocess.Popen", side_effect=local_observation):
            self.assertEqual(fx.f.report("feature")["DELIVERY_STATUS"], READY)
            old = runtime.begin_execution("unrelated")
            self.assertTrue(runtime.cancel(old))
            runtime.end_execution(old)
            report = fx.f.report("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertEqual(len(starts), 2)
        self.assertTrue(all(token is not None and token is not old for token in starts))
        self.assertIsNot(starts[0], starts[1])
        self.assertTrue(old.is_set())
        self.assertFalse(fx.f.cancel_requested("feature"))
        self.assertIsNone(runtime._active_execution)
        self.assertIsNone(runtime.current_process)


class PublicationTitleTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def remote(self, spec):
        class Capture(fixtures.FakeRemote):
            def api(self, endpoint, method="GET", data=None):
                if method in {"POST", "PATCH"}: self.title = data["title"]
                return super().api(endpoint, method, data)
        return Capture(self.fx.cwd, self.fx.root / "title.raw", spec, self.fx.target, self.fx.body)

    def test_first_nonempty_line_is_validated_before_publication(self):
        for objective, expected in [("Accepted feature", "Accepted feature"),
                                    ("\nAccepted feature", "Accepted feature"),
                                    (" \t\n\n  Accepted feature \t\nDetails", "Accepted feature")]:
            with self.subTest(objective=objective):
                spec = validate_mission({**self.fx.spec, "objective": objective})
                remote = self.remote(spec)
                remote.publish(fixtures.DELIVERY, spec, self.fx.target, self.fx.body)
                self.assertEqual(remote.title, expected)
                self.assertEqual(remote.writes, ["push", "create"])
                self.assertEqual(spec["objective"], objective, "不改变冻结的任务原文")

    def test_whitespace_only_title_is_rejected_before_any_write(self):
        for objective in ("", "\n \t \n"):
            with self.subTest(objective=objective):
                spec = {**self.fx.spec, "objective": objective}
                with self.assertRaises(ValueError): validate_mission(spec)
                remote, error = self.remote(spec), None
                try: remote.publish(fixtures.DELIVERY, spec, self.fx.target, self.fx.body)
                except Exception as exc: error = exc
                self.assertIsInstance(error, ValueError)
                self.assertEqual(remote.writes, [], "无效标题先产生了远端写入")


class MountAssertionTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def check_private_workspace(self, parent):
        with tempfile.TemporaryDirectory(prefix="cmh-private-mount-", dir=parent) as temporary:
            self.assertEqual(os.stat(temporary).st_mode & 0o777, 0o700)
            self.fx.cwd = Path(temporary) / "source"
            self.fx.test_container_argv_has_no_agent_socket_secrets_or_network()

    def test_private_workspace_beneath_home_is_allowed(self): self.check_private_workspace(Path.home())
    def test_private_workspace_in_tmp_is_allowed(self): self.check_private_workspace("/tmp")

    def test_actual_home_mount_is_rejected(self):
        original = fixtures.argv_for
        def unsafe(*args, **kwargs):
            argv = original(*args, **kwargs)
            argv[argv.index("--mount") + 1] = "type=bind,src=" + str(Path.home()) + ",dst=/app"
            return argv
        with patch.object(fixtures, "argv_for", side_effect=unsafe), self.assertRaises(AssertionError):
            self.fx.test_container_argv_has_no_agent_socket_secrets_or_network()

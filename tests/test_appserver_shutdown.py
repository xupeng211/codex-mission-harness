"""Real Linux child trees; only the AppServer workload/protocol is substituted.

No model, native sandbox, Docker, provider, or external service is started.
"""
import contextlib
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

from harness.appserver_process import AppServerProcess, process_identity
from harness.codex import AppServerCodex
from harness.factory_runtime import FactoryAppServer, LocalRuntime, RuntimeFailure
from harness.task_temp import TaskTempError, remove_directory


PAYLOAD = r'''
import json,os,signal,sys,time
from pathlib import Path
info,mode,factory=Path(sys.argv[1]),sys.argv[2],sys.argv[3]=='factory'
def record(role):
 fields=Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()
 row={'role':role,'pid':os.getpid(),'starttime':fields[19],'ppid':os.getppid(),
      'uid':os.getuid(),'pgid':os.getpgrp(),'sid':os.getsid(0),'state':fields[0]}
 fd=os.open(info,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
 os.write(fd,(json.dumps(row)+'\n').encode());os.close(fd)
if factory:assert json.loads(sys.stdin.readline())['method']=='initialized'
record('payload')
if mode in ('descendant','detached','doublefork','watchdog'):
 child=os.fork()
 if child==0:
  if mode!='descendant':os.setsid()
  if mode=='doublefork':
   record('intermediate')
   if os.fork()!=0:os._exit(0)
  signal.signal(signal.SIGTERM,signal.SIG_IGN)
  for fd in (0,1,2):os.close(fd)
  record('descendant')
  while True:time.sleep(.01)
 while len(info.read_text().splitlines())<(3 if mode=='doublefork' else 2):time.sleep(.005)
 if mode!='watchdog':os._exit(0)
if mode=='eof':os._exit(0)
while True:time.sleep(.01)
'''


def configuration_only_start(server, argv, *, record=None, **kwargs):
    """Existing argv/profile unit captures only; NOT a process-stop proof.

    Their Popen is an inert double. Real ownership/cleanup regressions below
    never use this helper. A configuration-only proof cannot pass delivery.
    """
    server.proc = subprocess.Popen(argv, **kwargs)
    temporary = getattr(server, "_task_temp", None)
    binding = {"temporary_workspace": temporary.identity if temporary else None}
    server._execution = types.SimpleNamespace(binding=binding, identity={"fixture_only": True},
        stop=lambda: {"confirmed": True, "proof": "configuration_only_fixture", "simulated": True})


class AppServerShutdownTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="appserver-shutdown-")
        self.root = Path(self.fixture.name)
        self.cwd, self.auth = self.root / "workspace", self.root / "auth"
        self.cwd.mkdir(mode=0o700); self.auth.mkdir(mode=0o700)
        subprocess.run(["git", "init", "-q", str(self.cwd)], check=True)
        (self.auth / "config.toml").write_text("")
        self.payload = self.root / "payload.py"; self.payload.write_text(PAYLOAD)
        self.profile = {"provider": "openai", "model": "fixture-no-inference", "codex_home": str(self.auth)}
        self.owners, self.servers, self.infos, self.observations = [], [], [], []
        self.libc = ctypes.CDLL(None, use_errno=True)
        old = ctypes.c_int()
        self.assertEqual(self.libc.prctl(37, ctypes.byref(old), 0, 0, 0), 0)
        self.old_subreaper = old.value
        self.assertEqual(self.libc.prctl(36, 1, 0, 0, 0), 0)
        self.addCleanup(self.release_fixtures)

    def wait_for(self, condition, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = condition()
            if value: return value
            time.sleep(.005)
        self.fail("own local process fixture did not reach its scheduled state")

    def alive(self, identity):
        try: actual = process_identity(identity["pid"])
        except FileNotFoundError: return False
        return all(actual[k] == identity[k] for k in ("pid", "starttime", "uid", "pgid", "sid")) and actual["state"] not in ("Z", "X")

    @contextlib.contextmanager
    def workload(self, mode="serve", legacy=False, initialize_error=False, on_initialize=None):
        original = AppServerProcess.start
        info = self.root / ("processes-" + str(len(self.infos)) + ".jsonl")
        self.infos.append(info)
        def launch(owner, argv, **kwargs):
            self.owners.append(owner)
            self.assertIn("app-server", argv)
            prefix = [] if legacy else argv[:4]  # Keep the real installed watchdog.
            actual = [*prefix, sys.executable, "-I", "-B", str(self.payload), str(info), mode,
                      "legacy" if legacy else "factory"]
            owner.fixture_launch = {"product_argv": list(map(str, argv)), "cwd": str(kwargs["cwd"]),
                "environment": {k:v for k,v in kwargs["env"].items() if k in
                    ("HOME", "PATH", "CODEX_HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "NO_COLOR")},
                "substituted_payload_argv": list(map(str, actual)), "workload": mode, "legacy": legacy}
            try:
                return original(owner, actual, **kwargs)
            finally:
                if owner.proc is not None:
                    owner.fixture_launch.update(supervisor_argv=list(map(str, owner.proc.args)),
                                                startup_identity=owner.identity)
        def initialize(server, method, params):
            self.servers.append(server)
            self.assertEqual(method, "initialize", "no thread/turn/model allowed")
            if on_initialize is not None: on_initialize(server)
            if initialize_error: raise RuntimeError("fixture initialization failed")
            return {"userAgent": "fixed-local-workload"}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(AppServerProcess, "start", launch))
            stack.enter_context(patch.object(FactoryAppServer, "_request", initialize))
            if legacy:
                stack.enter_context(patch.object(AppServerCodex, "_request", initialize))
                stack.enter_context(patch("harness.codex.require_builder_qualification"))
                builder = types.SimpleNamespace(model="fixture", reasoning_effort="high")
                stack.enter_context(patch("harness.codex.load_registry", return_value=types.SimpleNamespace(role=lambda _: builder)))
                stack.enter_context(patch.dict(os.environ, {"CODEX_HOME": str(self.auth)}))
            yield info

    def server(self, legacy=False, read_only=False, timeout=8):
        if legacy: return AppServerCodex(executable="/usr/bin/python3", worktree=str(self.cwd))
        return FactoryAppServer(self.profile, self.cwd, self.root / (str(len(self.owners)) + ".raw"), timeout, [], read_only)

    def children(self, info, count=1):
        return self.wait_for(lambda: [json.loads(v) for v in info.read_text().splitlines()]
                             if info.exists() and len(info.read_text().splitlines()) >= count else None)

    def assert_closed(self, server):
        proof = server._process_stop
        self.assertTrue(proof["confirmed"])
        self.assertEqual(proof["proof"], "ECHILD")
        self.assertFalse(server._task_temp.path.exists())
        self.assertTrue(server._task_temp_cleanup["cleanup_confirmed"])
        self.assertEqual(server._task_temp_cleanup["process_stop"], proof)
        self.assertIsNotNone(server.proc.returncode)
        self.observations.append({"proof": proof, "cleanup": server._task_temp_cleanup})

    def test_normal_and_exited_watchdog_with_term_ignoring_or_detached_descendant(self):
        guard_signal = self.root / "guard-signal"
        guard = subprocess.Popen([sys.executable, "-I", "-B", "-c",
            "import signal,time,pathlib,sys; signal.signal(signal.SIGTERM,lambda *_:pathlib.Path(sys.argv[1]).write_text('signal')); time.sleep(60)",
            str(guard_signal)], start_new_session=True)
        guard_identity = process_identity(guard.pid)
        try:
            for mode in ("serve", "descendant", "detached", "doublefork"):
                with self.subTest(mode=mode), self.workload(mode) as info:
                    server = self.server()
                    processes = self.children(info, 1 if mode == "serve" else 3 if mode == "doublefork" else 2)
                    self.assertTrue(server._task_temp.path.exists())
                    self.assertTrue(self.alive(processes[-1]))
                    original_close = server._task_temp.close
                    def cleanup_after_stop():
                        self.assertTrue(server._process_stop["confirmed"])
                        self.assertTrue(all(not self.alive(p) for p in processes))
                        return original_close()
                    with patch.object(server._task_temp, "close", side_effect=cleanup_after_stop):
                        server.close()
                    self.assert_closed(server)
                    if mode != "serve":
                        # The actual watchdog exits first; its subreaper remains
                        # unreaped and continues to own the surviving tree.
                        self.assertTrue(any(v["pid"] == server._execution.payload["pid"] for v in server._process_stop["reaped"]))
                        self.assertTrue(any(v["identity"]["pid"] == processes[-1]["pid"] and v["signal"] == signal.SIGKILL
                                            for v in server._process_stop["signals"]))
                    receipt = server._task_temp.cleanup_log.read_bytes()
                    server.close()
                    self.assertEqual(server._task_temp.cleanup_log.read_bytes(), receipt)
                    self.assertTrue(self.alive(guard_identity)); self.assertFalse(guard_signal.exists())
        finally:
            self.kill_exact(guard_identity); guard.wait(timeout=2)

    def test_legacy_uses_same_child_tree_boundary_even_after_setsid(self):
        with self.workload("detached", legacy=True) as info:
            server = self.server(legacy=True)
            processes = self.children(info, 2)
            server.close()
            self.assert_closed(server)
            self.assertTrue(all(not self.alive(p) for p in processes))

    def test_readonly_and_actual_watchdog_exit_still_require_child_tree_proof(self):
        with self.workload("watchdog") as info:
            server = self.server(read_only=True, timeout=1)
            processes = self.children(info, 2)
            self.assertIsNone(server._task_temp)
            # Observe this installed watchdog's exit without poll/reaping.
            # Factory retains the original absolute deadline even with EOF
            # queued: a response deadline must never be renewed by this test.
            watchdog = server._execution.payload
            self.wait_for(lambda: process_identity(watchdog["pid"])["state"] in ("Z", "X"), timeout=8)
            watchdog_exited = process_identity(watchdog["pid"])
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                server._read_message(time.monotonic() + 3)
            self.assertEqual(server._process_stop["proof"], "ECHILD")
            self.assertTrue(all(not self.alive(p) for p in processes))
            self.assertFalse(list(self.root.glob("*.temp.json")))
            self.observations.append({"read_only": True, "watchdog_timeout_seconds": 1,
                                      "watchdog_before_close": watchdog_exited, "proof": server._process_stop})

    def test_eof_deadline_initialization_and_start_failure_do_not_skip_stop(self):
        for mode in ("eof", "deadline", "initialize", "start"):
            with self.subTest(mode=mode), self.workload("eof" if mode == "eof" else "serve", initialize_error=mode == "initialize"):
                if mode == "start":
                    real_popen = subprocess.Popen
                    def cannot_start(argv, **kwargs):
                        if any(str(v).endswith("/appserver_process.py") for v in argv):
                            raise OSError("fixture cannot start helper")
                        return real_popen(argv, **kwargs)
                    with patch("harness.appserver_process.subprocess.Popen", side_effect=cannot_start):
                        with self.assertRaises(OSError): self.server()
                    self.assertEqual(self.owners[-1].stopped["proof"], "not_started")
                    self.assertFalse(Path(self.owners[-1].binding["temporary_workspace"]["path"]).exists())
                    continue
                if mode == "initialize":
                    with self.assertRaisesRegex(RuntimeError, "fixture initialization failed"): self.server()
                    server = self.servers[-1]
                else:
                    server = self.server()
                    with self.assertRaisesRegex(RuntimeError, "exited|deadline"):
                        server._read_message(time.monotonic() + (2 if mode == "eof" else .03))
                self.assert_closed(server)

    def test_runtime_reuse_and_nonreuse_release_only_after_proof(self):
        for reuse in (False, True):
            runtime = LocalRuntime(); execution = runtime.begin_execution("fixture-reuse")
            with self.subTest(reuse=reuse), self.workload() as info:
                def execute(server, *args, **kwargs):
                    self.children(info)
                    return {"output": {"summary": "fixture", "known_risks": []}}
                with patch.object(FactoryAppServer, "execute", execute):
                    runtime.agent("implement", self.profile, self.cwd, {"_reuse_session": reuse},
                                  self.root / ("runtime-" + str(reuse) + ".raw"), 8, [])
                    if reuse:
                        count = len(self.owners)
                        runtime.agent("implement", self.profile, self.cwd, {"_reuse_session": True},
                                      self.root / "second.raw", 8, [])
                        self.assertEqual(len(self.owners), count)
                        self.assertFalse(runtime.end_execution(execution))
                        self.assertTrue(runtime._single_server._task_temp.path.exists())
                        cleanup = runtime.close_session()
                        self.assertTrue(cleanup["process_stop"]["confirmed"])
                        self.assertIsNone(runtime.close_session())
                self.assertIsNone(runtime.current_process); self.assertIsNone(runtime._single_server)
                self.assertTrue(runtime.end_execution(execution))

    def test_cancel_and_operation_exception_stop_real_processes(self):
        for mode in ("cancel", "exception"):
            runtime = LocalRuntime(); execution = runtime.begin_execution(mode)
            with self.subTest(mode=mode), self.workload() as info:
                def execute(server, *args, **kwargs):
                    self.children(info)
                    if mode == "exception": raise KeyboardInterrupt("fixture interrupt")
                    self.assertTrue(runtime.cancel(execution))
                    server._read_message(time.monotonic() + 2)
                with patch.object(FactoryAppServer, "execute", execute):
                    with self.assertRaises(KeyboardInterrupt if mode == "exception" else RuntimeFailure):
                        runtime.agent("implement", self.profile, self.cwd, {}, self.root / (mode + ".raw"), 8, [])
                self.assert_closed(self.servers[-1])
                self.assertTrue(runtime.end_execution(execution))

    def test_reaped_or_changed_anchor_keeps_unknown_resources_and_execution_without_blind_signals(self):
        for fault in ("waited", "polled", "identity", "channel"):
            runtime = LocalRuntime(); execution = runtime.begin_execution("unknown-" + fault)
            with self.subTest(fault=fault), self.workload() as info:
                def execute(server, *args, **kwargs):
                    self.children(info)
                    owner = server._execution
                    if fault in ("waited", "polled"):
                        self.kill_exact(owner.identity)
                        if fault == "waited": owner.proc.wait(timeout=2)
                        else: self.wait_for(lambda: owner.proc.poll() is not None)
                    elif fault == "identity": owner.identity = {**owner.identity, "starttime": "wrong"}
                    else: owner.channel.close()
                    return {"output": {"summary": "operation finished", "known_risks": []}}
                with patch.object(FactoryAppServer, "execute", execute), \
                        patch("os.killpg", side_effect=AssertionError("never signal historical groups")):
                    with self.assertRaises(TaskTempError):
                        runtime.agent("implement", self.profile, self.cwd, {}, self.root / (fault + ".raw"), 8, [])
                    server = runtime._single_server
                    self.assertIsNotNone(server); self.assertTrue(server._task_temp.path.exists())
                    self.assertFalse(server._process_stop["confirmed"])
                    self.assertFalse(server._task_temp_cleanup["cleanup_confirmed"])
                    self.assertFalse(runtime.end_execution(execution))
                    self.assertIs(runtime.current_process, server.proc)
                    with self.assertRaises(TaskTempError): runtime.close_session()
                    self.assertIs(runtime._single_server, server)
                    with self.assertRaisesRegex(RuntimeError, "active execution"): runtime.begin_execution("other")
                    rows = [json.loads(v) for v in server._task_temp.cleanup_log.read_text().splitlines()]
                    self.assertTrue(rows); self.assertTrue(all(v["cleanup_confirmed"] is False for v in rows))
                    self.observations.append({"fault": fault, "stop": server._process_stop, "cleanup": rows,
                                              "runtime_retained": True, "replacement_dispatches": 0})

    def test_initialization_failure_retains_unknown_owner(self):
        runtime = LocalRuntime(); execution = runtime.begin_execution("initialization")
        with self.workload(initialize_error=True):
            original_stop = FactoryAppServer._stop_execution
            def lose_identity(server):
                server._execution.identity = None
                return original_stop(server)
            with patch.object(FactoryAppServer, "_stop_execution", lose_identity):
                with self.assertRaises(TaskTempError):
                    runtime.agent("implement", self.profile, self.cwd, {}, self.root / "init-unknown.raw", 8, [])
        self.assertIsNotNone(runtime._single_server)
        self.assertTrue(runtime._single_server._task_temp.path.exists())
        self.assertFalse(runtime.end_execution(execution))

    def test_cancellation_during_initialization_and_before_start(self):
        runtime = LocalRuntime(); execution = runtime.begin_execution("initializing")
        def cancel_initialize(server):
            self.assertIs(runtime._single_server, server)
            self.assertIs(runtime.current_process, server.proc)
            self.assertTrue(runtime.cancel(execution))
        with self.workload(on_initialize=cancel_initialize):
            with self.assertRaises((BrokenPipeError, RuntimeError)):
                runtime.agent("implement", self.profile, self.cwd, {}, self.root / "init-cancel.raw", 8, [])
        self.assert_closed(self.servers[-1])
        self.assertIsNone(runtime._single_server)
        self.assertTrue(runtime.end_execution(execution))
        runtime = LocalRuntime(); execution = runtime.begin_execution("cancelled-before-start")
        runtime.cancel(execution)
        with patch.object(AppServerProcess, "start", side_effect=AssertionError("no dispatch after cancellation")):
            with self.assertRaisesRegex(RuntimeFailure, "cancelled before"):
                runtime.agent("implement", self.profile, self.cwd, {}, self.root / "cancelled.raw", 8, [])
        self.assertTrue(runtime.end_execution(execution))

    def test_factory_report_and_resume_accept_real_stop_receipt_and_never_hide_unknown(self):
        from harness.factory import FactoryBlocked
        from harness.factory_fixture import AcceptanceRuntime
        from test_cleanup_identity import CleanupReceiptTests
        for fault in (False, True):
            with self.subTest(unknown=fault), self.workload() as info:
                fixture = CleanupReceiptTests()
                factory, _, mission = fixture.fixture()
                self.addCleanup(fixture.doCleanups)
                outer = self
                class Runtime(AcceptanceRuntime):
                    def __init__(self):
                        super().__init__(); self.holder = LocalRuntime()
                    def begin_execution(self, task): return self.holder.begin_execution(task)
                    def end_execution(self, execution): return self.holder.end_execution(execution)
                    def unconfirmed_appserver(self): return self.holder.unconfirmed_appserver()
                    def close_session(self): return self.holder.close_session()
                    def agent(self, role, profile, cwd, payload, transcript, timeout, denied):
                        if role not in ("implement", "rework"):
                            return super().agent(role, profile, cwd, payload, transcript, timeout, denied)
                        def execute(server, *args, **kwargs):
                            outer.children(info)
                            result = super(Runtime, self).agent(role, profile, cwd, payload, transcript, timeout, denied)
                            result["runtime_identity"]["native_runtime"] = server._native_identity
                            if fault: server._execution.identity = None
                            return result
                        with patch.object(FactoryAppServer, "execute", execute):
                            return self.holder.agent(role, {**profile, "codex_home": str(outer.auth)}, cwd,
                                {**payload, "_reuse_session": True}, transcript, min(8, timeout), denied)
                runtime = Runtime(); factory.runtime = runtime
                if fault:
                    with self.assertRaises(FactoryBlocked): factory.run(mission)
                    expected = "UNKNOWN"
                    self.assertIsNotNone(runtime.holder._single_server)
                    self.assertFalse(runtime.holder.end_execution(runtime.holder._active_execution))
                else:
                    expected = "READY_FOR_USER_ACCEPTANCE"
                    self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], expected)
                calls = list(runtime.calls)
                operations = [dict(v) for v in factory.db.execute("SELECT * FROM operations ORDER BY id")]
                self.assertEqual(factory.report(mission)["DELIVERY_STATUS"], expected)
                with patch.object(runtime, "agent", side_effect=AssertionError("no agent replay")), \
                        patch.object(runtime, "gate", side_effect=AssertionError("no validation replay")), \
                        patch.object(runtime, "second_review", side_effect=AssertionError("no review replay")):
                    self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], expected)
                self.assertEqual(runtime.calls, calls)
                self.assertEqual([dict(v) for v in factory.db.execute("SELECT * FROM operations ORDER BY id")], operations)
                from harness.factory import Factory
                from harness.factory_fixture import fixture_config
                reopened_runtime = AcceptanceRuntime()
                reopened = Factory(factory.root, fixture_config(), reopened_runtime)
                try:
                    self.assertEqual(reopened.report(mission)["DELIVERY_STATUS"], expected)
                    self.assertEqual(reopened.run(mission)["DELIVERY_STATUS"], expected)
                    self.assertEqual(reopened_runtime.calls, [])
                finally:
                    reopened.close()
                self.observations.append({"unknown": fault, "report_and_resume": expected, "replays": 0})

    def kill_exact(self, identity):
        if self.alive(identity):
            fd = os.pidfd_open(identity["pid"])
            try: signal.pidfd_send_signal(fd, signal.SIGKILL)
            finally: os.close(fd)

    def release_fixtures(self):
        # Test cleanup is outside the product assertion: only PIDs allocated
        # here and original TaskTemp objects; never a prefix/global kill scan.
        known = []
        for path in self.infos:
            if path.exists(): known.extend(json.loads(v) for v in path.read_text().splitlines())
        for owner in self.owners:
            if hasattr(owner, "payload"): known.append(owner.payload)
            if owner.proc is not None:
                try: current = process_identity(owner.proc.pid)
                except FileNotFoundError: continue
                # Even corrupted product metadata never supplies test cleanup
                # authority: this is our still-unreaped direct Popen child.
                if current["ppid"] == os.getpid() and owner.proc.returncode is None: known.append(current)
        for identity in known: self.kill_exact(identity)
        deadline = time.monotonic() + 3
        for identity in known:
            while time.monotonic() < deadline:
                try:
                    pid, _ = os.waitpid(identity["pid"], os.WNOHANG)
                    if pid: break
                except ChildProcessError: break
                time.sleep(.005)
        for owner in self.owners:
            if owner.proc is not None:
                if owner.proc.returncode is None: owner.proc.wait(timeout=2)
                for name in ("stdin", "stdout", "stderr"):
                    stream = getattr(owner.proc, name, None)
                    if stream is not None: stream.close()
            if owner.channel is not None: owner.channel.close()
            if owner.pidfd is not None: os.close(owner.pidfd); owner.pidfd = None
        for server in self.servers:
            temporary = getattr(server, "_task_temp", None)
            if temporary is not None and temporary.path.exists():
                remove_directory(temporary.path, temporary.identity, held_fd=temporary._fd)
                os.close(temporary._fd); temporary._fd = -1
        for identity in known: self.assertFalse(self.alive(identity), identity)
        self.assertEqual(self.libc.prctl(36, self.old_subreaper, 0, 0, 0), 0)
        destination = os.environ.get("CMH_PROCESS_SHUTDOWN_EVIDENCE")
        if destination:
            target = Path(destination); target.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw_records = {str(path.relative_to(self.root)): path.read_text()
                           for pattern in ("*.process.jsonl", "*.temp.json", "*.temp.cleanup.jsonl", "*.temp.claims.jsonl")
                           for path in self.root.rglob(pattern)}
            (target / (self._testMethodName + ".json")).write_text(json.dumps({"observations": self.observations,
                "launches": [getattr(owner, "fixture_launch", {}) for owner in self.owners],
                "server_stop_and_cleanup": [{"stop": getattr(server, "_process_stop", None),
                    "cleanup": getattr(server, "_task_temp_cleanup", None)} for server in self.servers],
                "raw_product_records": raw_records,
                "own_process_identities": known, "all_owned_processes_stopped": True,
                "boundary": "real product supervisor/stop/TaskTemp; fixed Python workload, initialize and execute only",
                "test_teardown": "After UNKNOWN preservation assertions, exact own fixture PIDs/resources reclaimed by test driver; this is not product cleanup success"}, indent=2) + "\n")
        self.fixture.cleanup()


if __name__ == "__main__":
    unittest.main()

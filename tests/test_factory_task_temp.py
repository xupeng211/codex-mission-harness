"""Delegated filesystem boundaries, using CLI sandbox only; never AppServer turns."""
import contextlib
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from harness.codex import AppServerCodex
from harness.factory_runtime import FactoryAppServer, LocalRuntime
from test_appserver_shutdown import configuration_only_start


PAYLOAD = r'''
import datetime,errno,json,os,pathlib,socket
S=__SETTINGS__
def emit(row):
 row['time']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 print(json.dumps(row),flush=True)
def observe(name,operation,path,fn):
 row={'event':'file','name':name,'operation':operation,'path':str(path),'exception_type':None,'errno':None}
 try:row.update(value=fn(),observed='ALLOWED')
 except Exception as exc:
  code=getattr(exc,'errno',None)
  row.update(observed='NOT_VISIBLE' if code==errno.ENOENT else 'DENIED' if code in (errno.EACCES,errno.EPERM,errno.EROFS) else 'UNKNOWN',exception_type=type(exc).__name__,errno=code,message=str(exc))
 emit(row)
emit({'event':'start','cwd':os.getcwd(),'environment':dict(os.environ)})
for name,path in S['markers'].items():
 p=pathlib.Path(path)
 observe(name,'read',p,lambda p=p:p.read_text())
 observe(name,'write',p,lambda p=p:p.write_text('WRITTEN:'+S['label']+'\n'))
observe('mapping','mountinfo','/proc/self/mountinfo',lambda:pathlib.Path('/proc/self/mountinfo').read_text())
sock=None
try:
 sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 emit({'event':'network','operation':'create','observed':'ALLOWED'})
except Exception as exc:emit({'event':'network','operation':'create','observed':'DENIED' if getattr(exc,'errno',None) in (errno.EPERM,errno.EACCES) else 'UNKNOWN','exception_type':type(exc).__name__,'errno':getattr(exc,'errno',None),'message':str(exc)})
try:
 if sock is not None:
  sock.settimeout(1);sock.connect(('127.0.0.1',S['port']))
  emit({'event':'network','operation':'connect','observed':'ALLOWED','fixture_only':True})
 else:emit({'event':'network','operation':'connect','observed':'NOT_ATTEMPTED','reason':'socket creation denied'})
except Exception as exc:emit({'event':'network','operation':'connect','observed':'DENIED' if getattr(exc,'errno',None) in (errno.EPERM,errno.EACCES) else 'UNKNOWN','exception_type':type(exc).__name__,'errno':getattr(exc,'errno',None),'message':str(exc)})
finally:
 try:
  if sock is not None:sock.close()
  emit({'event':'network','operation':'close','observed':'CLOSED' if sock is not None else 'NOT_NEEDED'})
 except Exception as exc:emit({'event':'network','operation':'close','observed':'UNKNOWN','exception_type':type(exc).__name__,'errno':getattr(exc,'errno',None)})
emit({'event':'complete'})
'''


def marker_facts(markers):
    rows = {}
    for name, path in markers.items():
        p = Path(path)
        data = p.read_bytes()
        rows[name] = {"path": str(p), "exists": True, "content": data.decode(),
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "mode": oct(stat.S_IMODE(p.stat().st_mode)), "is_symlink": p.is_symlink(),
                      "link_target": os.readlink(p) if p.is_symlink() else None}
    return rows


def inert_process():
    return types.SimpleNamespace(stdin=io.StringIO(), stdout=io.StringIO(), stderr=None,
                                 poll=lambda: 0)


def run_boundary_case(location, read_only=False, legacy=False, named_profile=False, proxy=False):
    """Capture real product configuration; stub only AppServer process/RPCs."""
    label = ("legacy-" if legacy else "factory-") + location + ("-readonly" if read_only else "-developer")
    label += "-named" if named_profile else "-proxy" if proxy else ""
    results = {"label": label, "legacy": legacy, "read_only": read_only}
    with contextlib.ExitStack() as stack:
        parent = "/tmp" if location == "tmp" else str(Path.home())
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="cmh-temp-boundary-", dir=parent)))
        shared = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="cmh-other-user-", dir="/tmp")))
        other = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="cmh-other-task-", dir="/tmp")))
        cwd, auth, source = root / "state/candidates/fixture", root / "auth", root / "source"
        for p in (cwd, auth, source):
            p.mkdir(parents=True, mode=0o700)
        subprocess.run(["git", "init", "-q", str(cwd)], check=True)
        # On the old version the same fixture remains an ordinary simulated task.
        # The fixed version additionally uses the actual trusted allocator for it.
        try:
            from harness.task_temp import TaskTemp
        except ImportError:
            TaskTemp = None
        other_resource = None
        if TaskTemp is not None:
            other_cwd = root / "other-candidate"
            other_cwd.mkdir(mode=0o700)
            subprocess.run(["git", "init", "-q", str(other_cwd)], check=True)
            other_resource = TaskTemp(str(other_cwd), "cmh_delegated_other_fixture")
            stack.callback(other_resource.close)
            other = other_resource.path
            results["other_task_identity"] = other_resource.identity
        (auth / "config.toml").write_text("")
        if named_profile:
            (auth / "boundary.config.toml").write_text('default_permissions=":workspace"\n[shell_environment_policy.set]\nTMPDIR="/tmp"\nTMP="/tmp"\nTEMP="/tmp"\n')
        markers = {"workspace": cwd / "marker", "scope": cwd / "scope.json",
                   "git": cwd / ".git/marker", "controller": root / "state/control/marker",
                   "evidence": root / "state/evidence/marker", "budget": root / "state/budget/marker",
                   "original": source / "marker", "auth": auth / "marker",
                   "ordinary_tmp": shared / "marker", "other_task": other / "marker"}
        for name, p in markers.items():
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            p.write_text("INITIAL:" + name + "\n")
            p.chmod(0o600)
        real_popen = subprocess.Popen
        def capture(argv, *args, **kwargs):
            if "app-server" not in list(map(str, argv)):
                return real_popen(argv, *args, **kwargs)
            results["product_launch"] = {"argv": list(map(str, argv)), "cwd": str(kwargs["cwd"]),
                                         "env": kwargs["env"], "intercepted": True}
            return inert_process()
        def rpc(server, method, params):
            if method != "initialize":
                raise AssertionError("No actual AppServer/thread/turn allowed: " + method)
            return {"userAgent": "fixture-only-no-AppServer"}
        def execute(server, *args, **kwargs):
            server._policy_params(str(cwd))
            resource = getattr(server, "_task_temp", None)
            own = resource.path if resource else shared / "old-unallocated-scratch"
            own.mkdir(exist_ok=True, mode=0o700)
            markers["own_temp"] = own / "marker"
            markers["own_temp"].write_text("INITIAL:own-temp\n")
            markers["own_temp"].chmod(0o600)
            markers["other_task_link"] = own / "other-task-link"
            markers["other_task_link"].symlink_to(markers["other_task"])
            if proxy:
                markers["proxy_auth"] = Path(results["product_launch"]["env"]["CODEX_HOME"]) / "marker"
                markers["proxy_auth"].write_text("fixture-only-proxy-auth-marker")
                markers["proxy_auth"].chmod(0o600)
            results["task_temp"] = dict(resource.identity) if resource else None
            results["before"] = marker_facts(markers)
            launch = results["product_launch"]
            idx = launch["argv"].index("app-server")
            base = launch["argv"][4:idx] if not legacy else launch["argv"][:idx]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0)); listener.listen(1)
                settings = {"label": label, "markers": {k: str(v) for k, v in markers.items()},
                            "port": listener.getsockname()[1]}
                payload = PAYLOAD.replace("__SETTINGS__", repr(settings))
                compile(payload, "<permission-payload>", "exec")
                command = [*base, "sandbox", "--permission-profile", server._permissions_profile,
                           "--cd", str(cwd), "--", "/usr/bin/python3", "-I", "-B", "-c", payload]
                results["command"] = {"argv": command, "cwd": str(cwd), "env": launch["env"],
                                      "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
                completed = subprocess.run(command, cwd=cwd, env=launch["env"], text=True,
                                           capture_output=True, timeout=30)
                results["command"].update(exit_code=completed.returncode,
                                         ended_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            results.update(stdout=completed.stdout, stderr=completed.stderr,
                           events=[json.loads(x) for x in completed.stdout.splitlines()], after=marker_facts(markers))
            return {"output": {"summary": "native CLI fixture only", "known_risks": []}}
        stack.enter_context(patch("harness.codex.subprocess.Popen", side_effect=capture))
        stack.enter_context(patch.object(AppServerCodex, "_start_process", configuration_only_start))
        stack.enter_context(patch.object(FactoryAppServer, "_request", rpc))
        if legacy:
            stack.enter_context(patch("harness.codex.require_builder_qualification"))
            registry = types.SimpleNamespace(role=lambda role: types.SimpleNamespace(model="fixture-no-inference", reasoning_effort="high"))
            stack.enter_context(patch("harness.codex.load_registry", return_value=registry))
            stack.enter_context(patch.dict(os.environ, {"CODEX_HOME": str(auth)}))
            stack.enter_context(patch.object(AppServerCodex, "_request", rpc))
            adapter = AppServerCodex(worktree=str(cwd))
            try:
                execute(adapter)
            finally:
                adapter.close()
        else:
            profile = {"provider": "openai", "model": "fixture-no-inference", "codex_home": str(auth)}
            if named_profile:
                profile["codex_profile"] = "boundary"
            if proxy:
                policy = root / "policy/private.json"
                policy.parent.mkdir(mode=0o700)
                policy.write_text("{}")  # Relay/Provider itself is never started.
                profile["transport"] = {"type": "cli_proxy", "endpoint": "http://127.0.0.1:1/v1",
                                        "configured_provider": "fixture", "policy_file": str(policy)}
                relay = types.SimpleNamespace(base_url="http://127.0.0.1:1/v1", nonce="fixture-observer-capability",
                                              close=lambda: None)
                stack.enter_context(patch("harness.factory_runtime.ProxyRelay", return_value=relay))
            stack.enter_context(patch.object(FactoryAppServer, "execute", execute))
            LocalRuntime().agent("review" if read_only else "implement",
                                 profile,
                                 cwd, {"mission_scope_file": "scope.json"}, root / "run.raw", 30,
                                 [root / "state", source])
        results["allocated_temp_removed"] = not Path(results["task_temp"]["path"]).exists() if results["task_temp"] else None
    results["fixture_roots_removed"] = all(not p.exists() for p in (root, shared, other))
    destination = os.environ.get("CMH_TASK_TEMP_EVIDENCE")
    if destination:
        p = Path(destination) / (label + ".json")
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        p.write_text(json.dumps(results, indent=2) + "\n")
    return results


@unittest.skipUnless(shutil.which("codex") and shutil.which("bwrap"), "native CLI sandbox/bubblewrap required")
class NativeTaskTempTests(unittest.TestCase):
    def check_boundary(self, result):
        self.assertEqual(result["command"]["exit_code"], 0, result["stderr"])
        self.assertTrue(any(x.get("event") == "complete" for x in result["events"]), result["stdout"])
        start = next(x for x in result["events"] if x.get("event") == "start")
        self.assertEqual(start["cwd"], result["product_launch"]["cwd"])
        command = result["command"]["argv"]
        self.assertEqual(command[command.index("--cd") + 1], start["cwd"])
        observations = {(x["name"], x["operation"]): x for x in result["events"] if x.get("event") == "file"}
        # These assertions also fail meaningfully on the old real CLI profile.
        for name in ("ordinary_tmp", "other_task", "other_task_link"):
            for operation in ("read", "write"):
                self.assertIn(observations[name, operation]["observed"], ("DENIED", "NOT_VISIBLE"), observations[name, operation])
        self.assertEqual(observations["workspace", "read"]["observed"], "ALLOWED")
        writable = not result["read_only"]
        self.assertEqual(observations["workspace", "write"]["observed"], "ALLOWED" if writable else "DENIED")
        if writable:
            self.assertIsNotNone(result["task_temp"])
            self.assertEqual(observations["own_temp", "read"]["observed"], "ALLOWED")
            self.assertEqual(observations["own_temp", "write"]["observed"], "ALLOWED")
            self.assertTrue(result["allocated_temp_removed"])
        else:
            self.assertIsNone(result["task_temp"])
            self.assertIn(observations["own_temp", "read"]["observed"], ("DENIED", "NOT_VISIBLE"))
            self.assertIn(observations["own_temp", "write"]["observed"], ("DENIED", "NOT_VISIBLE"))
        if not result["legacy"]:
            for name in ("scope", "git"):
                self.assertEqual(observations[name, "read"]["observed"], "ALLOWED")
                self.assertEqual(observations[name, "write"]["observed"], "DENIED")
            for name in ("controller", "evidence", "budget", "original", "auth"):
                for op in ("read", "write"):
                    self.assertIn(observations[name, op]["observed"], ("DENIED", "NOT_VISIBLE"))
        else:
            for op in ("read", "write"):
                self.assertIn(observations["auth", op]["observed"], ("DENIED", "NOT_VISIBLE"))
        if "proxy_auth" in result["before"]:
            for op in ("read", "write"):
                self.assertIn(observations["proxy_auth", op]["observed"], ("DENIED", "NOT_VISIBLE"))
        for name in result["before"]:
            if name == "workspace" and writable or name == "own_temp" and writable or result["legacy"] and name not in ("ordinary_tmp", "other_task", "other_task_link", "auth", "git"):
                continue
            self.assertEqual(result["before"][name], result["after"][name], name)
        self.assertEqual(next(x["observed"] for x in result["events"] if x.get("event") == "network" and x["operation"] == "create"), "DENIED")
        self.assertTrue(result["fixture_roots_removed"])

    def test_developer_isolated_temp_in_tmp_and_home(self):
        for location in ("tmp", "home"):
            with self.subTest(location=location):
                self.check_boundary(run_boundary_case(location))

    def test_readonly_keeps_temp_and_workspace_readonly(self):
        for location in ("tmp", "home"):
            with self.subTest(location=location):
                self.check_boundary(run_boundary_case(location, read_only=True))

    def test_legacy_delegated_cli_also_isolates_temp(self):
        self.check_boundary(run_boundary_case("home", legacy=True))

    def test_named_profile_and_proxy_configuration_keep_exact_temp_boundary(self):
        self.check_boundary(run_boundary_case("home", named_profile=True))
        self.check_boundary(run_boundary_case("home", proxy=True))


class TaskTempLifecycleTests(unittest.TestCase):
    def setUp(self):
        from harness.task_temp import TaskTemp, TaskTempError
        self.TaskTemp, self.TaskTempError = TaskTemp, TaskTempError
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.cwd = self.root / "workspace"
        self.cwd.mkdir()
        subprocess.run(["git", "init", "-q", str(self.cwd)], check=True)
        subprocess.run(["git", "-C", str(self.cwd), "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost",
                        "commit", "--allow-empty", "-qm", "baseline"], check=True)
        self.auth = self.root / "auth"
        self.auth.mkdir(mode=0o700)
        self.profile = {"provider": "openai", "model": "fixture-no-inference", "codex_home": str(self.auth)}

    @contextlib.contextmanager
    def stub_appserver(self, execute):
        popen = subprocess.Popen
        def launch(argv, *args, **kwargs):
            return inert_process() if "app-server" in list(map(str, argv)) else popen(argv, *args, **kwargs)
        with patch("harness.codex.subprocess.Popen", side_effect=launch), \
                patch.object(AppServerCodex, "_start_process", configuration_only_start), \
                patch.object(FactoryAppServer, "_request", return_value={}), \
                patch.object(FactoryAppServer, "execute", execute):
            yield

    def test_success_failure_and_cancel_close_only_owned_resources(self):
        from harness.factory_runtime import RuntimeFailure
        for mode in ("success", "failure", "cancel"):
            runtime = LocalRuntime()
            execution = runtime.begin_execution(mode)
            resources = []
            other = self.TaskTemp(str(self.cwd), "cmh_delegated_other")
            try:
                def execute(server, *args, **kwargs):
                    resource = server._task_temp
                    resources.append(resource)
                    server._thread_policy_params(str(self.cwd))
                    # A candidate-created link must not make cleanup follow another task.
                    (resource.path / "link").symlink_to(other.path, target_is_directory=True)
                    (other.path / "marker").write_text("other-task-unchanged")
                    if mode == "cancel":
                        self.assertTrue(runtime.cancel(execution))
                    if mode != "success":
                        raise RuntimeError("fixture execution " + mode)
                    return {"output": {}}
                with self.stub_appserver(execute):
                    call = lambda: runtime.agent("implement", self.profile, self.cwd, {}, self.root / (mode + ".raw"), 10, [])
                    if mode == "success":
                        call()
                    else:
                        with self.assertRaises(RuntimeFailure):
                            call()
                self.assertEqual(len(resources), 1)
                self.assertFalse(resources[0].path.exists())
                self.assertEqual((other.path / "marker").read_text(), "other-task-unchanged")
                allocation = self.root / (mode + ".temp.json")
                self.assertEqual(json.loads(allocation.read_text()), resources[0].identity)
                cleanup = json.loads(resources[0].cleanup_log.read_text().splitlines()[-1])
                self.assertTrue(cleanup["cleanup_confirmed"])
                self.assertTrue(runtime.end_execution(execution))
            finally:
                other.close()

    def test_reuse_verifies_identity_and_new_session_never_adopts_old_scratch(self):
        runtime = LocalRuntime()
        calls = []
        def execute(server, *args, **kwargs):
            server._policy_params(str(self.cwd))
            calls.append(server._task_temp)
            return {"output": {}}
        with self.stub_appserver(execute):
            for i in range(2):
                runtime.agent("implement", self.profile, self.cwd, {"_reuse_session": True}, self.root / f"reuse-{i}.raw", 10, [])
            self.assertIs(calls[0], calls[1])
            old = calls[0]
            old.path.chmod(0o755)
            try:
                with self.assertRaises(self.TaskTempError):
                    runtime.agent("implement", self.profile, self.cwd, {"_reuse_session": True}, self.root / "bad.raw", 10, [])
                self.assertEqual(len(calls), 2, "identity failure must precede execution")
                with self.assertRaises(self.TaskTempError):
                    runtime.close_session()
                with self.assertRaisesRegex(RuntimeError, "active execution"):
                    runtime.begin_execution("other-mission")
            finally:
                old.path.chmod(0o700)
                runtime.close_session()
            runtime.agent("implement", self.profile, self.cwd, {}, self.root / "fresh.raw", 10, [])
            self.assertNotEqual(calls[-1].path, old.path)
            self.assertFalse(old.path.exists())
            self.assertFalse(calls[-1].path.exists())

    def test_root_replacement_symlink_binding_and_mode_mismatch_fail_closed(self):
        resource = self.TaskTemp(str(self.cwd), "cmh_delegated_original")
        other = self.TaskTemp(str(self.cwd), "cmh_delegated_other")
        original = resource.path
        moved = original.with_name(original.name + "-held-fixture")
        try:
            with self.assertRaises(self.TaskTempError):
                resource.validate(str(self.cwd), "cmh_delegated_other")
            original.rename(moved)
            original.mkdir(mode=0o700)
            (original / "marker").write_text("replacement-must-survive")
            with self.assertRaises(self.TaskTempError):
                resource.close()
            self.assertEqual((original / "marker").read_text(), "replacement-must-survive")
            (original / "marker").unlink(); original.rmdir()
            original.symlink_to(other.path, target_is_directory=True)
            with self.assertRaises(self.TaskTempError):
                resource.close()
            self.assertTrue(other.path.is_dir())
            original.unlink(); moved.rename(original)
        finally:
            if moved.exists():
                if original.is_symlink(): original.unlink()
                if not original.exists(): moved.rename(original)
            resource.close(); other.close()

    def test_startup_failure_releases_allocated_temp(self):
        popen = subprocess.Popen
        def launch(argv, *args, **kwargs):
            if "app-server" in list(map(str, argv)):
                raise RuntimeError("fixture startup failure")
            return popen(argv, *args, **kwargs)
        with patch("harness.codex.subprocess.Popen", side_effect=launch):
            with self.assertRaisesRegex(RuntimeError, "fixture startup failure"):
                FactoryAppServer(self.profile, self.cwd, self.root / "startup.raw", 10, [], False)
        identity = json.loads((self.root / "startup.temp.json").read_text())
        self.assertFalse(Path(identity["path"]).exists())
        self.assertTrue(json.loads((self.root / "startup.temp.cleanup.jsonl").read_text())["cleanup_confirmed"])

    def test_unbound_allocation_reports_exact_path_without_deleting_it(self):
        with patch("harness.task_temp.os.open", side_effect=PermissionError("fixture open failure")):
            with self.assertRaises(self.TaskTempError) as caught:
                self.TaskTemp(str(self.cwd), "cmh_delegated_fixture")
        identity = caught.exception.identity
        path = Path(identity["path"])
        try:
            self.assertFalse(identity["allocation_confirmed"])
            self.assertIn("cleanup unconfirmed", str(caught.exception))
            self.assertTrue(path.is_dir(), "an unbound resource must not be removed by guessing")
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        finally:
            # The fixture's exact new empty directory, not a prefix scan.
            path.rmdir()

    def test_unreadable_cleanup_receipt_retains_session_ownership(self):
        runtime = LocalRuntime()
        with self.stub_appserver(lambda server, *args, **kwargs: {"output": {}}):
            runtime.agent("implement", self.profile, self.cwd, {"_reuse_session": True},
                          self.root / "receipt.raw", 10, [])
        server = runtime._single_server
        try:
            with patch.object(Path, "read_bytes", side_effect=PermissionError("fixture receipt unreadable")):
                with self.assertRaisesRegex(self.TaskTempError, "receipt is unconfirmed"):
                    runtime.close_session()
            self.assertIs(runtime._single_server, server)
            self.assertFalse(server._task_temp.path.exists())
            self.assertIn("no replacement execution", runtime.unconfirmed_appserver())
            with self.assertRaisesRegex(RuntimeError, "active execution"):
                runtime.begin_execution("another-task")
        finally:
            receipt = runtime.close_session()
        self.assertTrue(receipt["cleanup_confirmed"])
        self.assertIsNone(runtime.unconfirmed_appserver())
        self.assertEqual(receipt["evidence"]["sha256"], hashlib.sha256(server._task_temp.cleanup_log.read_bytes()).hexdigest())

    def test_nonreused_cleanup_failure_retains_exact_resource(self):
        runtime = LocalRuntime()
        resources = []
        def execute(server, *args, **kwargs):
            resources.append(server._task_temp)
            server._task_temp.path.chmod(0o755)
            return {"output": {}}
        try:
            with self.stub_appserver(execute):
                with self.assertRaises(self.TaskTempError):
                    runtime.agent("implement", self.profile, self.cwd, {}, self.root / "nonreuse.raw", 10, [])
            self.assertIs(runtime._single_server._task_temp, resources[0])
            with self.assertRaisesRegex(RuntimeError, "active execution"):
                runtime.begin_execution("another-task")
        finally:
            for resource in resources:
                resource.path.chmod(0o700)
            runtime.close_session()
        self.assertFalse(resources[0].path.exists())

    def test_protected_parent_cannot_be_reopened_as_scratch(self):
        created = []
        allocate = tempfile.mkdtemp
        def remember(*args, **kwargs):
            path = allocate(*args, **kwargs)
            created.append(Path(path))
            return path
        with patch("harness.task_temp.tempfile.mkdtemp", side_effect=remember):
            with self.assertRaisesRegex(self.TaskTempError, "protected root"):
                self.TaskTemp(str(self.cwd), "cmh_delegated_fixture", (Path("/tmp"),))
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created), "allocation and private cleanup parent must both be removed")

    def test_cleanup_failure_is_durable_unknown_and_resume_does_not_dispatch(self):
        from harness.factory import Factory, FactoryBlocked
        from harness.factory_fixture import AcceptanceRuntime, fixture_config
        error_type = self.TaskTempError
        class Runtime(AcceptanceRuntime):
            fail_cleanup = True
            def close_session(self):
                if self.fail_cleanup:
                    self.fail_cleanup = False
                    raise error_type("fixture task cleanup unconfirmed", {"path": str(self_root / "unconfirmed")})
        self_root = self.root
        factory = Factory(self.root / "state", fixture_config(), Runtime())
        self.addCleanup(factory.close)
        mission = factory.submit({"version": 2, "mission_id": "temp-cleanup", "repository": str(self.cwd),
                                  "objective": "fixture only"})
        factory.prepare(mission)
        with patch.object(factory, "_run", return_value={"DELIVERY_STATUS": "READY"}) as execute:
            with self.assertRaises(FactoryBlocked):
                factory.run(mission)
            self.assertEqual(execute.call_count, 1)
        self.assertEqual(factory.row(mission)["status"], "UNKNOWN")
        before = factory.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        result = factory.run(mission)
        self.assertEqual(result["DELIVERY_STATUS"], "UNKNOWN")
        self.assertIn("no replay or resource adoption", result["BLOCKERS_REMAINING"][0])
        self.assertEqual(factory.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], before)


if __name__ == "__main__":
    unittest.main()

"""P1/P2 regressions: synthetic auth/gh/receipt semantics, real local process trees.

No real credentials, GitHub, models or Docker. Final-gate/PR-state control flow,
Factory.report, execution ownership and subreaper evidence remain production code.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from harness.adapters import FootballPredictionAdapter
from harness.appserver_process import AppServerProcess
from harness.factory import READY
from harness.factory_runtime import LocalRuntime, RuntimeFailure
from test_factory_review_lifecycle import offline_review_summaries
import test_factory_controller_gates as fixtures


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="review-regressions-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cwd = self.root / "candidate"
        self.cwd.mkdir(mode=0o700)
        self.spec = {"mission_id": "fixture"}
        self.target = {"base": "a" * 40, "head": "b" * 40,
                       "mission_scope_file": "mission.json"}
        self.runtime = LocalRuntime()
        self.reviews = offline_review_summaries(self.root, self.spec, self.cwd, self.target)
        self.result = self.reviews[0]["canonical_execution"]

    @contextmanager
    def consumer(self, code=None, before=None, runtime=None):
        """Replace only semantic consumer workload; keep actual argv/stop binding."""
        runtime = runtime or self.runtime
        original = runtime._supervised_review_step
        default = "import json; print(json.dumps({'status':'PASS','evidence':'OFFLINE semantic consumer only','artifact':None,'data':{}}))"
        def step(binding, argv, *args, **kwargs):
            if before:
                before(binding)
            actual = [sys.executable, "-I", "-B", "-c", code or default]
            return original({**binding, "argv": actual}, actual, *args, **kwargs)
        with patch("harness.factory_project.verify_target"), \
                patch.object(runtime, "_supervised_review_step", side_effect=step):
            yield

    def validate(self):
        return self.runtime.project_validate_review(self.spec, self.cwd, self.target, "reviewer", self.result)

    def test_final_gate_preserves_synthetic_auth_across_worker_and_gh_boundaries(self):
        home = self.root / "home"
        home.mkdir(mode=0o700)
        config = home / ".config" / "gh"
        config.mkdir(parents=True, mode=0o700)
        (config / "synthetic-auth").write_text("offline-only")
        gh = self.root / "gh-double"
        # Deliberately mismatched PR HEAD stops the real merge_ready after the
        # authenticated PR read, before any canonical merge/remote action.
        pr = {"number": 7, "state": "open", "head": {"sha": "c" * 40},
              "base": {"sha": "a" * 40, "ref": "main"}, "body": "OFFLINE"}
        original_step = self.runtime._supervised_review_step
        for mode in ("GH_TOKEN", "GITHUB_TOKEN", "config"):
            with self.subTest(mode=mode):
                seen = self.root / (mode + ".gh.json")
                worker_seen = self.root / (mode + ".worker.json")
                gh.write_text(f'''#!{sys.executable}
import json,os,sys
from pathlib import Path
assert sys.argv[1:] == ['api','repos/offline/repo/pulls/7']
info={{'home_ok':os.environ.get('HOME')=={str(home)!r},
      'config_ok':os.environ.get('GH_CONFIG_DIR')=={str(config)!r},
      'unsafe_present':any(k in os.environ for k in ['OPENAI_API_KEY','BUILDER_ONLY_SECRET','PYTHONPATH','GIT_DIR'])}}
info['auth_ok']=os.environ.get({mode!r})=='synthetic-only' if {mode!r}!='config' else Path(os.environ.get('GH_CONFIG_DIR','/nonexistent'),'synthetic-auth').is_file()
Path({str(seen)!r}).write_text(json.dumps(info))
if not info['auth_ok']:sys.exit(18)
print({json.dumps(pr)!r})
''')
                gh.chmod(0o700)
                setup = ("import os; from pathlib import Path; "
                    "from harness.adapters import FootballPredictionAdapter; "
                    f"Path({str(worker_seen)!r}).write_text(json.dumps({{'home_ok':os.environ.get('HOME')=={str(home)!r},"
                    "'unsafe_present':any(k in os.environ for k in ['OPENAI_API_KEY','BUILDER_ONLY_SECRET','PYTHONPATH','GIT_DIR'])})); "
                    f"FootballPredictionAdapter._gh=staticmethod(lambda *a:[{str(gh)!r},*a]); "
                    "original_command=FootballPredictionAdapter._trusted_command_argv; "
                    f"FootballPredictionAdapter._trusted_command_argv=classmethod(lambda cls,a:list(a) if a[0]=={str(gh)!r} else original_command(a)); ")
                def step(binding, argv, *args, **kwargs):
                    actual = list(argv)
                    i = actual.index("-c") + 1
                    marker = "r=FootballPredictionContract().final_gate"
                    self.assertIn(marker, actual[i])
                    actual[i] = actual[i].replace(marker, setup + marker)
                    return original_step({**binding, "argv": actual}, actual, *args, **kwargs)
                env = {"HOME": str(home), "GH_CONFIG_DIR": str(config),
                       "XDG_CONFIG_HOME": str(home / ".config"), "PATH": os.defpath,
                       "OPENAI_API_KEY": "synthetic-builder-secret", "BUILDER_ONLY_SECRET": "synthetic",
                       "PYTHONPATH": "/synthetic/unsafe", "GIT_DIR": "/synthetic/unsafe"}
                if mode != "config":
                    env[mode] = "synthetic-only"
                with patch.dict(os.environ, env, clear=True), \
                        patch("harness.factory_project.verify_target"), \
                        patch.object(self.runtime, "_supervised_review_step", side_effect=step):
                    gate = self.runtime.project_final_gate(self.spec, self.cwd, self.target, self.reviews,
                        self.root / (mode + ".raw"), 5, context={"pr_number": 7, "pr_repo": "offline/repo",
                            "pr_base_sha": "a" * 40, "ci_status": "PASS"})
                self.assertEqual(gate["reason"], "PR identity/base no longer matches exact reviewed approval")
                self.assertEqual(json.loads(worker_seen.read_text()), {"home_ok": True, "unsafe_present": False})
                self.assertEqual(json.loads(seen.read_text()), {"home_ok": True, "config_ok": True,
                                                              "unsafe_present": False, "auth_ok": True})
                self.assertEqual(json.loads(Path(gate["validation_lifecycle"]["path"]).read_text())["stop"]["proof"], "ECHILD")
                # The AI lane continues to get the actual isolated environment.
                with patch.dict(os.environ, env, clear=True):
                    review_env = FootballPredictionAdapter().review_environment("deepseek", worktree=str(self.cwd), base=self.target["base"])
                    _, proof = self.runtime._supervised_review_step(
                        {"stage": "offline-review-env", "argv": [sys.executable, "-I", "-B", "-c", "import os; assert os.environ['HOME']=='/nonexistent'; assert not any(k in os.environ for k in ['GH_TOKEN','GITHUB_TOKEN','GH_CONFIG_DIR','OPENAI_API_KEY','BUILDER_ONLY_SECRET'])"]},
                        [sys.executable, "-I", "-B", "-c", "import os; assert os.environ['HOME']=='/nonexistent'; assert not any(k in os.environ for k in ['GH_TOKEN','GITHUB_TOKEN','GH_CONFIG_DIR','OPENAI_API_KEY','BUILDER_ONLY_SECRET'])"],
                        self.cwd, review_env, self.root / (mode + ".review-isolation"), 5)
                    self.assertEqual(json.loads(Path(proof["path"]).read_text())["exit_code"], 0)

    def test_standalone_validation_after_cancel_uses_new_identity_and_releases_it(self):
        old = self.runtime.begin_execution("old")
        self.assertTrue(self.runtime.cancel(old))
        self.assertTrue(self.runtime.end_execution(old))
        tokens = []
        def observe(binding):
            tokens.append(self.runtime._active_execution)
            self.assertIsNotNone(tokens[-1])
            self.assertIsNot(tokens[-1], old)
            self.assertEqual(self.runtime._active_mission, "fixture")
            self.assertFalse(self.runtime.cancel(old))
            self.assertIsNone(self.runtime.end_execution(old))
        with self.consumer(before=observe):
            for _ in range(2):
                checked = self.validate()
                self.assertEqual(checked.status, "PASS")
                self.assertIsNone(self.runtime._active_execution)
                self.assertIsNone(self.runtime._execution_id)
                self.runtime.assert_canonical_lifecycles(self.root, "fixture")
        self.assertIsNot(tokens[0], tokens[1])
        self.assertTrue(old.is_set(), "old cancellation must never be cleared")

    def test_active_other_mission_or_thread_cannot_be_stolen_and_creates_no_request(self):
        for mission, foreign_thread in (("other", False), ("fixture", True)):
            with self.subTest(mission=mission, foreign_thread=foreign_thread):
                active = self.runtime.begin_execution(mission)
                before = set(self.root.iterdir())
                errors = []
                def work():
                    try:
                        self.validate()
                    except BaseException as exc:
                        errors.append(exc)
                try:
                    with self.consumer():
                        if foreign_thread:
                            thread = threading.Thread(target=work)
                            thread.start(); thread.join(5)
                            self.assertFalse(thread.is_alive())
                        else:
                            work()
                    self.assertEqual(len(errors), 1, errors)
                    self.assertIn("different active execution", str(errors[0]))
                    self.assertEqual(before, set(self.root.iterdir()))
                    self.assertIs(self.runtime._active_execution, active)
                finally:
                    self.runtime.end_execution(active)

    def test_cancelled_current_execution_is_not_reset_or_given_a_request(self):
        active = self.runtime.begin_execution("fixture")
        self.runtime.cancel(active)
        before = set(self.root.iterdir())
        try:
            with self.consumer(), self.assertRaisesRegex(RuntimeFailure, "cancelled"):
                self.validate()
            self.assertEqual(before, set(self.root.iterdir()))
            self.assertTrue(active.is_set())
            self.assertIs(self.runtime._active_execution, active)
        finally:
            self.runtime.end_execution(active)

    def test_cancellation_just_before_validator_admission_leaves_no_unstarted_request(self):
        before = set(self.root.iterdir())
        def cancel(_binding):
            self.assertTrue(self.runtime.cancel(self.runtime._active_execution))
        with self.consumer(before=cancel), self.assertRaisesRegex(RuntimeFailure, "cancelled"):
            self.validate()
        self.assertEqual(before, set(self.root.iterdir()))
        self.assertIsNone(self.runtime._active_execution)
        self.runtime.assert_canonical_lifecycles(self.root, "fixture")

    def test_late_old_cancel_does_not_stop_a_live_standalone_validator(self):
        old = self.runtime.begin_execution("old")
        self.runtime.cancel(old); self.runtime.end_execution(old)
        ready, release = self.root / "validator.ready", self.root / "validator.release"
        code = f"""import json,time
from pathlib import Path
Path({str(ready)!r}).write_text('ready')
while not Path({str(release)!r}).exists():time.sleep(.01)
print(json.dumps({{'status':'PASS','evidence':'OFFLINE consumer','artifact':None,'data':{{}}}}))
"""
        outputs, errors = [], []
        def work():
            try:
                outputs.append(self.validate())
            except BaseException as exc:
                errors.append(exc)
        with self.consumer(code=code):
            worker = threading.Thread(target=work)
            worker.start()
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and worker.is_alive() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists(), errors)
                active = self.runtime._active_execution
                self.assertIsNotNone(active)
                self.assertIsNot(active, old)
                self.assertFalse(self.runtime.cancel(old))
                self.runtime.end_execution(old)
                self.assertIs(self.runtime._active_execution, active)
                self.assertFalse(active.is_set())
            finally:
                release.write_text('release')
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(outputs[0].status, "PASS")
        self.assertIsNone(self.runtime._active_execution)
        self.runtime.assert_canonical_lifecycles(self.root, "fixture")

    def test_stop_unknown_keeps_standalone_identity_and_blocks_replacement(self):
        original = AppServerProcess.stop
        def unknown(owner):
            original(owner)  # Real cleanup; only proof acceptance is an injected fault.
            raise RuntimeError("injected stop UNKNOWN")
        with self.consumer(), patch.object(AppServerProcess, "stop", unknown), self.assertRaisesRegex(RuntimeError, "UNKNOWN"):
            self.validate()
        self.assertIsNotNone(self.runtime._active_execution)
        self.assertIsNotNone(self.runtime._review_owner)
        self.assertTrue(list(self.root.glob("*.validator-*.input.json")))
        self.assertFalse(list(self.root.glob("*.validator-*.stop.json")))
        before = set(self.root.iterdir())
        with self.consumer(), self.assertRaises((RuntimeError, RuntimeFailure)):
            self.validate()
        self.assertEqual(before, set(self.root.iterdir()))
        with self.assertRaises(RuntimeError):
            self.runtime.begin_execution("other")

    def test_report_revalidates_after_unrelated_cancel_on_same_runtime(self):
        class Runtime(fixtures.LiveProtocolDouble, LocalRuntime):
            def __init__(self):
                fixtures.LiveProtocolDouble.__init__(self)
                LocalRuntime.__init__(self)
                self.real_validation = False

            def project_review(self, spec, cwd, target, lane, transcript, timeout, **kwargs):
                from harness.factory_project import review_process_binding
                result = fixtures.LiveProtocolDouble.project_review(self, spec, cwd, target, lane, transcript, timeout, **kwargs)
                argv = [sys.executable, "-I", "-B", "-c", "pass"]
                result["executed_runner_argv"] = argv
                _, proof = self._supervised_review_step(review_process_binding(spec, cwd, target, lane, result),
                    argv, cwd, {"PATH": os.defpath}, transcript.with_suffix(".review"), 5)
                result["review_lifecycle"] = proof
                return result

            def project_validate_review(self, *args, **kwargs):
                method = LocalRuntime.project_validate_review if self.real_validation else fixtures.LiveProtocolDouble.project_validate_review
                return method(self, *args, **kwargs)

        fx = fixtures.FactoryLiveProtocolTests()
        fx.setUp(); self.addCleanup(fx.doCleanups)
        runtime = Runtime()
        fx.f.runtime = runtime
        ready = fx.f.run("feature")
        self.assertEqual(ready["DELIVERY_STATUS"], READY)
        by_lane = {r["lane"]: r for r in ready["REVIEW_RESULT"]}
        runtime.real_validation = True
        old = runtime.begin_execution("unrelated")
        self.assertTrue(runtime.cancel(old)); self.assertTrue(runtime.end_execution(old))
        starts, original = [], runtime._supervised_review_step
        def step(binding, argv, *args, **kwargs):
            starts.append(runtime._active_execution)
            review = by_lane[binding["lane"]]
            output = {"status": "PASS", "evidence": "OFFLINE receipt semantics only",
                      "artifact": review["canonical_receipt"], "data": review["canonical_receipt_data"]}
            actual = [sys.executable, "-I", "-B", "-c", "print(" + repr(json.dumps(output)) + ")"]
            return original({**binding, "argv": actual}, actual, *args, **kwargs)
        with patch.object(runtime, "_supervised_review_step", side_effect=step), \
                patch("harness.factory_project.verify_target",
                      side_effect=lambda spec, cwd, target: self.assertEqual(fx.f.target(spec, cwd), target)):
            report = fx.f.report("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report["BLOCKERS_REMAINING"])
        self.assertEqual(len(starts), 2)
        self.assertTrue(all(token is not None and token is not old for token in starts))
        self.assertTrue(old.is_set())
        self.assertIsNone(runtime._active_execution)
        runtime.assert_canonical_lifecycles(fx.f.root / "evidence" / "feature", "feature")


if __name__ == "__main__":
    unittest.main()

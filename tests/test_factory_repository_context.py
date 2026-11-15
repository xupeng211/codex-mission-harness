"""Offline repository-context regressions; no GitHub, receipts or model approvals.

Exercise the real adapter entrypoints, environment isolation and local processes.
Only GitHub responses and canonical workloads are doubles; the probe's synthetic
PASS is a transport assertion, never evidence of a real canonical gate passing.
"""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from harness.adapters import FootballPredictionAdapter


class RepositoryContextTests(unittest.TestCase):
    REPO = "fixture/football"
    BASE = "a" * 40
    HEAD = "b" * 40

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="repository-context-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cwd = self.root / "candidate"
        self.cwd.mkdir()
        self.git("init", "-q")
        self.config = self.cwd / ".git" / "config"
        self.scope = self.cwd / "scope.json"
        self.scope.write_text("{}")
        self.adapter = FootballPredictionAdapter()
        self.pr = {"number": 7, "state": "open", "body": "OFFLINE TEST DATA",
                   "head": {"sha": self.HEAD},
                   "base": {"ref": "main", "sha": self.BASE,
                            "repo": {"full_name": self.REPO}}}
        self.calls = []

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.cwd), *args], text=True,
            env={"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": os.devnull}, stderr=subprocess.PIPE).strip()

    @contextmanager
    def offline(self, *, raw=None, reply=None, exit_code=0, preflight_exit=0):
        original_run = subprocess.run
        config_bytes, remotes = self.config.read_bytes(), self.git("remote")

        def workload(argv, **kwargs):
            code = argv[argv.index("-c") + 1] if "-c" in argv else ""
            stage = next((s for s in ("pr-ready-check", "agent-workflow", "agent-preflight")
                          if s in code), None)
            self.assertIsNotNone(stage, "unexpected process in offline gate test")
            expected = None if stage == "agent-preflight" else self.REPO
            response = None if stage == "agent-preflight" else reply
            code = preflight_exit if stage == "agent-preflight" else exit_code
            # A real Git child must see the process-only origin; no network I/O.
            probe = f"""
import json, os, subprocess, sys
p = subprocess.run(['git', '-C', {str(self.cwd)!r}, 'config', '--get',
                    'remote.origin.url'], text=True, capture_output=True)
origin = p.stdout.strip() or None
expected = {expected!r}
identity_ok = expected is None or origin == 'https://github.com/' + expected + '.git'
data = {{'verdict': 'PASS', 'merge_ready': 'YES', 'pr': {{'head_sha': {self.HEAD!r}}},
        'findings': [{{'name': 'required-check:OFFLINE-unit', 'passed': True,
                      'message': 'OFFLINE TEST DATA'}}]}}
if {response!r} is not None:
    data = json.loads({json.dumps(response)!r})
if not identity_ok:
    data.update(verdict='FAIL', merge_ready='NO')
data['_probe'] = {{'origin': origin, 'identity_ok': identity_ok,
    'env': {{k: v for k, v in os.environ.items() if k.startswith('GIT_')
             or k in ('GH_REPO', 'GH_HOST', 'PYTHONPATH', 'LD_PRELOAD')}}}}
print(json.dumps(data))
sys.exit({code!r} if identity_ok else 2)
"""
            actual = list(argv)
            actual[actual.index("-c") + 1] = probe
            result = original_run(actual, **kwargs)
            self.calls.append((stage, json.loads(result.stdout)["_probe"]))
            return result

        hostile = {"PATH": os.defpath, "HOME": str(self.root),
                   "GH_REPO": "attacker/other", "GH_HOST": "attacker.invalid",
                   "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "remote.origin.url",
                   "GIT_CONFIG_VALUE_0": "https://github.com/attacker/other.git",
                   "GIT_CONFIG_KEY_1": "core.sshCommand", "GIT_CONFIG_VALUE_1": "evil",
                   "GIT_CONFIG_PARAMETERS": "'core.bare=true'", "GIT_DIR": "/evil",
                   "GIT_WORK_TREE": "/evil", "GIT_CONFIG_GLOBAL": "/evil",
                   "GIT_SSH_COMMAND": "evil", "PYTHONPATH": "/evil",
                   "LD_PRELOAD": "/evil"}
        with patch.dict(os.environ, hostile, clear=True), \
                patch.object(self.adapter, "_run", return_value=json.dumps(
                    self.pr if raw is None else raw)) as remote, \
                patch.object(self.adapter, "_trusted_base_checkout", return_value=self.root), \
                patch("harness.adapters.subprocess.run", side_effect=workload):
            yield remote
        self.assertEqual(self.config.read_bytes(), config_bytes)
        self.assertEqual(self.git("remote"), remotes)

    def ci(self, **kwargs):
        args = dict(worktree=str(self.cwd), head=self.HEAD, pr_number=7,
                    pr_repo=self.REPO, base_sha=self.BASE, pr_base_sha=self.BASE)
        args.update(kwargs)
        return self.adapter.ci(**args)

    def merge_ready(self, **kwargs):
        args = dict(worktree=str(self.cwd), base=self.BASE, head=self.HEAD,
                    mission_id="offline", scope_file=str(self.scope), pr_number=7,
                    pr_repo=self.REPO, pr_base_sha=self.BASE,
                    receipts={"codex": "OFFLINE-NOT-A-REAL-RECEIPT.json"}, ci_status="PASS")
        args.update(kwargs)
        return self.adapter.merge_ready(**args)

    def assert_context(self, probe, *, repository=True):
        env = probe["env"]
        self.assertTrue(probe["identity_ok"])
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1" if repository else "0")
        if repository:
            self.assertEqual(env["GH_REPO"], self.REPO)
            self.assertEqual(env["GIT_CONFIG_KEY_0"], "remote.origin.url")
            self.assertEqual(env["GIT_CONFIG_VALUE_0"],
                             f"https://github.com/{self.REPO}.git")
        self.assertEqual(env["GH_HOST"], "github.com")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_SSH_COMMAND", "GIT_CONFIG_PARAMETERS",
                    "GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_1", "PYTHONPATH", "LD_PRELOAD"):
            self.assertNotIn(key, env)

    def test_ci_passes_trusted_context_to_remote_free_candidate_and_git_child(self):
        with self.offline():
            result = self.ci()
        self.assertEqual(result.status, "PASS")
        self.assertEqual([c[0] for c in self.calls], ["pr-ready-check"])
        self.assert_context(self.calls[0][1])

    def test_final_gate_uses_context_but_local_preflight_stays_isolated(self):
        with self.offline():
            result = self.merge_ready()
        self.assertEqual(result.status, "PASS")
        self.assertEqual([c[0] for c in self.calls], ["agent-preflight", "agent-workflow"])
        self.assert_context(self.calls[0][1], repository=False)
        self.assertIsNone(self.calls[0][1]["origin"])
        self.assert_context(self.calls[1][1])

    def test_candidate_origin_cannot_override_verified_pr_context(self):
        self.git("config", "remote.origin.url", "https://github.com/attacker/other.git")
        for entry in (self.ci, self.merge_ready):
            with self.subTest(entry=entry.__name__), self.offline():
                self.assertEqual(entry().status, "PASS")
        self.assertEqual(self.git("config", "remote.origin.url"),
                         "https://github.com/attacker/other.git")

    def test_changed_pr_head_after_ci_still_blocks(self):
        changed = copy.deepcopy(self.pr)
        changed["head"]["sha"] = "c" * 40
        with self.offline() as remote:
            remote.side_effect = [json.dumps(self.pr), json.dumps(changed)]
            self.assertEqual(self.ci().status, "BLOCKED_EXTERNAL")
        self.assert_context(self.calls[0][1])

    def test_environment_probes_fall_back_from_untrusted_running_python(self):
        trusted = self.adapter._trusted_system_executable("python3")
        directory = self.root / "runner-python"
        directory.mkdir(mode=0o700)
        executable = directory / "python3"
        shutil.copyfile(trusted, executable)
        # Exercise real validation, without changing any host interpreter or
        # bypassing the executable/ancestor checks used by production calls.
        for file_mode, directory_mode, reason in (
                (0o775, 0o700, "unsafe ownership or permissions"),
                (0o755, 0o777, "unsafe parent directory")):
            executable.chmod(file_mode)
            directory.chmod(directory_mode)
            with self.subTest(reason=reason):
                denied = self.adapter._call([str(executable), "--version"])
                self.assertEqual(denied.returncode, 127, denied.stderr)
                self.assertEqual(denied.stdout, "")
                self.assertIn(reason, denied.stderr)
                with patch("harness.adapters.sys.executable", str(executable)):
                    self.assertEqual(self.adapter._trusted_python_interpreter(), trusted)
                    for name in (
                            "test_explicit_environment_cannot_override_trusted_repository",
                            "test_other_commands_keep_original_isolation"):
                        with self.subTest(probe=name):
                            getattr(self, name)()

    def test_explicit_environment_cannot_override_trusted_repository(self):
        code = "import json,os; print(json.dumps(dict(os.environ)))"
        with patch.dict(os.environ, {}, clear=True):
            result = self.adapter._call(
                [self.adapter._trusted_python_interpreter(), "-I", "-c", code],
                repository=self.REPO, env={"GH_REPO": "attacker/other",
                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.sshCommand",
                    "GIT_CONFIG_VALUE_0": "evil", "GIT_DIR": "/evil"})
        self.assertEqual(result.returncode, 0,
                         f"argv={result.args!r}; stdout={result.stdout!r}; stderr={result.stderr!r}")
        self.assert_context({"identity_ok": True, "env": json.loads(result.stdout)})

    def test_other_commands_keep_original_isolation(self):
        with patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1", "GIT_DIR": "/evil",
                "GIT_CONFIG_KEY_0": "remote.origin.url", "GIT_CONFIG_VALUE_0": "evil"},
                clear=True):
            result = self.adapter._call(
                [self.adapter._trusted_python_interpreter(), "-I", "-c",
                "import json,os; print(json.dumps(dict(os.environ)))"])
        self.assertEqual(result.returncode, 0,
                         f"argv={result.args!r}; stdout={result.stdout!r}; stderr={result.stderr!r}")
        env = json.loads(result.stdout)
        self.assertEqual(env["GIT_CONFIG_COUNT"], "0")
        self.assertNotIn("GIT_CONFIG_KEY_0", env)
        self.assertNotIn("GIT_DIR", env)

    def test_invalid_repository_or_pr_is_rejected_before_remote_or_gate(self):
        cases = [{"pr_repo": x} for x in ("../repo", "owner/..", "owner/repo/extra",
                 "owner/repo?x=1", "https://github.com/owner/repo", "owner/repo\n", None)]
        cases += [{"pr_number": x} for x in (0, -1, True, "7/../../other")]
        for args in cases:
            for entry in (self.ci, self.merge_ready):
                with self.subTest(args=args, entry=entry.__name__), self.offline() as remote:
                    self.assertEqual(entry(**args).status, "BLOCKED_EXTERNAL")
                    remote.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_pr_identity_mismatch_rejected_before_canonical_workload(self):
        for field, value in (("number", 8), ("repository", "attacker/other"),
                             ("head", "c" * 40), ("base", "c" * 40), ("state", "closed")):
            raw = copy.deepcopy(self.pr)
            if field == "repository":
                raw["base"]["repo"]["full_name"] = value
            elif field in {"head", "base"}:
                raw[field]["sha"] = value
            else:
                raw[field] = value
            for entry in (self.ci, self.merge_ready):
                with self.subTest(field=field, entry=entry.__name__), self.offline(raw=raw):
                    self.assertEqual(entry().status, "BLOCKED_EXTERNAL")
        self.assertEqual(self.calls, [])

    def test_ci_still_blocks_failed_missing_or_wrong_head_evidence(self):
        cases = [("FAIL", {"verdict": "FAIL", "pr": {"head_sha": self.HEAD},
                   "findings": [{"name": "required-check:OFFLINE", "passed": False}]}),
                 ("BLOCKED_EXTERNAL", {"verdict": "PASS", "pr": {"head_sha": self.HEAD},
                                       "findings": []}),
                 ("BLOCKED_EXTERNAL", {"verdict": "PASS", "pr": {"head_sha": "c" * 40},
                    "findings": [{"name": "required-check:OFFLINE", "passed": True}]})]
        for status, reply in cases:
            with self.subTest(status=status), self.offline(reply=reply):
                self.assertEqual(self.ci().status, status)

    def test_ci_nonzero_exit_cannot_claim_pass(self):
        with self.offline(exit_code=1):
            self.assertEqual(self.ci().status, "BLOCKED_EXTERNAL")

    def test_final_gate_preserves_receipt_rejection_and_nonzero_exit(self):
        for reply, code in (({"merge_ready": "NO", "reason": "OFFLINE receipt failure"}, 1),
                            ({"merge_ready": "YES"}, 1), ({}, 0)):
            with self.subTest(reply=reply), self.offline(reply=reply, exit_code=code):
                self.assertEqual(self.merge_ready().status, "BLOCKED_EXTERNAL")
                self.assertEqual(self.calls[-1][0], "agent-workflow")
                self.assert_context(self.calls[-1][1])

    def test_failed_local_preflight_never_reaches_final_gate(self):
        with self.offline(preflight_exit=1):
            self.assertEqual(self.merge_ready().status, "BLOCKED_EXTERNAL")
        self.assertEqual([c[0] for c in self.calls], ["agent-preflight"])

    def test_missing_receipt_stops_before_remote_lookup(self):
        with self.offline() as remote:
            self.assertEqual(self.merge_ready(receipts={}).status, "BLOCKED_EXTERNAL")
            remote.assert_not_called()
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()

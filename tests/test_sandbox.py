from __future__ import annotations

import os
import pwd
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.sandbox import SandboxUnavailable, _git_config, _trusted_bwrap, preflight_project_gate, project_gate_invocation


class ProjectGateSandboxTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cmh-gate-sandbox-test-")
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Harness Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "harness@example.invalid"], check=True)
        (self.repo / "tracked.txt").write_text("candidate\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "fixture"], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "config", "http.extraheader",
            "Authorization: Basic controller-secret-marker",
        ], check=True)
        self.worktree = self.root / "candidate-worktree"
        subprocess.run([
            "git", "-C", str(self.repo), "worktree", "add", "-q", "-b", "candidate",
            str(self.worktree), "HEAD",
        ], check=True)
        self.logs = self.root / "logs"
        self.logs.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, job_id="sandbox-test", env=None, cwd=None):
        with patch("harness.sandbox._trusted_bwrap", return_value="/usr/bin/bwrap"):
            return project_gate_invocation(
                ["make", "verify-pr"], str(cwd or self.worktree), env or {}, self.logs, job_id,
            )

    def test_git_config_returns_default_for_missing_key_and_text_for_present_key(self):
        self.assertEqual(_git_config(self.worktree, "harness.missing-key", "fallback"), "fallback")
        self.assertEqual(_git_config(self.worktree, "core.repositoryformatversion", "fallback"), "0")

    def test_gate_invocation_clears_environment_masks_credentials_and_network(self):
        invocation = self.build(env={"COMPOSE_PROJECT_NAME": "cmh-test"})
        argv = invocation.argv
        self.assertIn("--unshare-all", argv)
        self.assertIn("--clearenv", argv)
        self.assertIn("--tmpfs", argv)
        self.assertIn(("--tmpfs", "/"), tuple(zip(argv, argv[1:])))
        self.assertNotIn("GH_TOKEN", invocation.env)
        self.assertNotIn("HTTP_PROXY", invocation.env)
        self.assertNotIn("controller-secret-marker", invocation.config_path.read_text())
        common = subprocess.check_output(
            ["git", "-C", str(self.worktree), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            text=True,
        ).strip()
        self.assertIn(("--ro-bind", common), tuple(zip(argv, argv[1:])))
        ro_bind_pairs = [
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv[:-2])
            if item == "--ro-bind"
        ]
        self.assertNotIn(("/", "/"), ro_bind_pairs)
        self.assertIn(("/usr", "/usr"), ro_bind_pairs)
        self.assertIn((str(self.worktree / ".git"), "/mnt/.git"), ro_bind_pairs)
        ro_bind_pairs = [
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv[:-2])
            if item == "--ro-bind"
        ]
        self.assertIn((str(self.worktree), "/mnt"), ro_bind_pairs)
        self.assertNotIn("--bind", argv)
        self.assertEqual(invocation.env["COMPOSE_PROJECT_NAME"], "cmh-test")

    def test_regular_checkout_sanitizes_original_and_sandbox_git_config_paths(self):
        with patch("harness.sandbox.shutil.which", return_value="/usr/bin/bwrap"):
            invocation = project_gate_invocation(
                ["make", "verify-pr"], str(self.repo), {}, self.logs, "regular-checkout",
            )
        argv = invocation.argv
        ro_bind_pairs = [
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv[:-2])
            if item == "--ro-bind"
        ]
        common = self.repo / ".git"
        self.assertIn((str(invocation.config_path), str(common / "config")), ro_bind_pairs)
        self.assertIn((str(invocation.config_path), "/mnt/.git/config"), ro_bind_pairs)
        # This fixture lives under /tmp, which the sandbox masks. The helper
        # recreates only the target parents before mounting the sanitized file.
        self.assertIn(str(common), argv)
        self.assertIn("--dir", argv)
        self.assertNotIn("controller-secret-marker", invocation.config_path.read_text())

    def test_scope_and_pr_body_are_mapped_to_only_the_approved_sandbox_mounts(self):
        scope = self.worktree / "tracked.txt"
        scope.write_text("mutated after commit\n", encoding="utf-8")
        scope_mode = scope.stat().st_mode & 0o777
        evidence = self.worktree.parent / ".cmh-gate-evidence" / "mission" / ("a" * 40)
        evidence.mkdir(parents=True)
        body = evidence / "pr-body.md"
        body.write_text("review context\n", encoding="utf-8")
        body.chmod(0o600)
        head = subprocess.check_output(["git", "-C", str(self.worktree), "rev-parse", "HEAD"], text=True).strip()
        invocation = self.build(env={
            "MISSION_SCOPE_FILE": str(scope),
            "PR_BODY": str(body),
            "BASE_REF": "b" * 40,
            "HEAD_REF": head,
            "JSON": "1",
        })
        self.assertEqual(invocation.env["MISSION_SCOPE_FILE"], "/mnt/tracked.txt")
        self.assertEqual(invocation.env["PR_BODY"], "/tmp/cmh-pr-evidence/pr-body.md")
        self.assertIn(str(evidence), invocation.argv)
        self.assertIn("/tmp/cmh-pr-evidence", invocation.argv)
        ro_bind_pairs = [
            (invocation.argv[index + 1], invocation.argv[index + 2])
            for index, item in enumerate(invocation.argv[:-2])
            if item == "--ro-bind"
        ]
        scope_sources = [source for source, target in ro_bind_pairs if target == "/mnt/tracked.txt"]
        self.assertEqual(len(scope_sources), 1)
        self.assertEqual(Path(scope_sources[0]).read_bytes(), b"candidate\n")
        self.assertEqual(scope.stat().st_mode & 0o777, scope_mode)

    def test_gate_rejects_controller_credentials_and_scope_outside_worktree(self):
        with self.assertRaisesRegex(SandboxUnavailable, "environment value outside the allowlist"):
            self.build(env={"GH_TOKEN": "controller-secret-marker"})
        with self.assertRaisesRegex(SandboxUnavailable, "scope file is outside"):
            self.build(env={"MISSION_SCOPE_FILE": str(self.root / "secret.txt")})

    def test_missing_bubblewrap_fails_closed(self):
        with patch("harness.sandbox.shutil.which", return_value=None):
            with self.assertRaisesRegex(SandboxUnavailable, "bubblewrap is required"):
                project_gate_invocation(["make", "verify-pr"], str(self.worktree), {}, self.logs, "no-bwrap")

    def test_writable_bubblewrap_launcher_is_rejected_before_preflight(self):
        fake = self.root / "bwrap"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o700)
        with patch("harness.sandbox.shutil.which", return_value=str(fake)):
            with self.assertRaisesRegex(SandboxUnavailable, "executable is not trusted"):
                _trusted_bwrap()

    def test_isolation_preflight_runs_only_a_harmless_command_and_fails_closed(self):
        invocation = self.build()
        success = subprocess.CompletedProcess([], 0, "", "")
        with patch("harness.sandbox.subprocess.run", return_value=success) as run:
            preflight_project_gate(invocation)
        launched = run.call_args.args[0]
        self.assertEqual(launched[launched.index("--") + 1:], ["/bin/true"])
        failure = subprocess.CompletedProcess([], 1, "", "namespace unavailable")
        with patch("harness.sandbox.subprocess.run", return_value=failure):
            with self.assertRaisesRegex(SandboxUnavailable, "preflight exited 1"):
                preflight_project_gate(invocation)

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is not installed")
    def test_candidate_makefile_cannot_read_host_credentials_or_git_auth_config(self):
        host_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        gitfile = self.worktree / ".git"
        gitfile_before = gitfile.read_bytes()
        makefile = self.worktree / "Makefile"
        makefile.write_text(
            "gate-check:\n"
            f"\t@test ! -e {shlex.quote(str(host_home / '.codex'))}\n"
            "\t@test ! -e /run/docker.sock\n"
            "\t@test ! -e /etc/shadow\n"
            "\t@test ! -e /var/lib\n"
            "\t@test ! -e /opt\n"
            "\t@test -x /usr/bin/python3\n"
            "\t@test \"$$(cat tracked.txt)\" = candidate\n"
            "\t@! printf 'scope-tamper\\n' > tracked.txt 2>/dev/null\n"
            "\t@test -z \"$${GH_TOKEN:-}\"\n"
            "\t@! git config --local --get http.extraheader >/dev/null 2>&1\n"
            "\t@! printf 'gitdir: /tmp/cmh-fake-gitdir\\n' > .git 2>/dev/null\n"
            "\t@! touch sandbox-output.txt 2>/dev/null\n",
            encoding="utf-8",
        )
        invocation = project_gate_invocation(
            ["make", "gate-check"], str(self.worktree), {
                "MISSION_SCOPE_FILE": str(self.worktree / "tracked.txt"),
                "HEAD_REF": subprocess.check_output(
                    ["git", "-C", str(self.worktree), "rev-parse", "HEAD"], text=True,
                ).strip(),
            }, self.logs, "hostile-makefile",
        )
        host_env = {**os.environ, "GH_TOKEN": "controller-secret-marker"}
        result = subprocess.run(
            invocation.argv, cwd=invocation.cwd, env=host_env,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertFalse((self.worktree / "sandbox-output.txt").exists())
        self.assertEqual((self.worktree / "tracked.txt").read_text(encoding="utf-8"), "candidate\n")
        self.assertEqual(gitfile.read_bytes(), gitfile_before)


if __name__ == "__main__":
    unittest.main()

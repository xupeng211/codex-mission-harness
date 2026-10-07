"""Installed official runtime compatibility, with zero model inference requests."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from harness.factory import Factory, git
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_runtime import FactoryAppServer, LocalRuntime


@unittest.skipUnless(shutil.which("codex") and shutil.which("bwrap"), "installed Codex/bubblewrap required for offline native protocol verification")
class NativeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        (self.source / "score.py").write_text("def add(a, b):\n    return a + b\n")
        git(self.source, "add", ".")
        git(self.source, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "baseline")
        self.factory = Factory(self.root / "state", fixture_config(), AcceptanceRuntime())
        self.addCleanup(self.factory.close)
        self.factory.submit({"version": 2, "mission_id": "native", "repository": str(self.source), "objective": "offline protocol only"})
        self.spec, self.cwd = self.factory.prepare("native")
        self.auth = self.root / "private-codex-home"
        self.auth.mkdir(mode=0o700)
        (self.auth / "private-sentinel").write_text("not-a-real-credential")
        (self.root / "state/control/private-sentinel").write_text("not-visible-to-agent")

    def server(self, read_only):
        server = FactoryAppServer({"provider": "openai", "model": "offline-protocol-no-inference", "codex_home": str(self.auth)},
                                  self.cwd, self.root / ("review.raw" if read_only else "develop.raw"),
                                  30, [self.root / "state", self.source], read_only, read_only)
        self.addCleanup(server.close)
        server.start_or_resume(None, str(self.cwd))
        self.assertEqual(server.runtime_identity["provider"], "openai")
        return server

    def exec(self, server, code):
        result = server._request("command/exec", {"command": ["/usr/bin/python3", "-c", code], "cwd": str(self.cwd),
                                                  "permissions": server._permissions_profile, "timeoutMs": 10000})
        self.assertEqual(result["exitCode"], 0, result)
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events), "offline compatibility must never start model inference")
        return json.loads(result["stdout"])

    def test_developer_official_permissions_allow_source_and_deny_auth_controller_original_git_write(self):
        server = self.server(False)
        paths = {"source": str(self.cwd / "score.py"), "auth": str(self.auth / "private-sentinel"),
                 "controller": str(self.root / "state/control/private-sentinel"), "original": str(self.source / "score.py")}
        code = "import pathlib,json\nr={}\nfor k,p in " + repr(paths) + ".items():\n try: pathlib.Path(p).read_bytes();r[k]='READABLE'\n except OSError:r[k]='DENIED'\n"
        write_paths = {"edit": str(self.cwd / "edit-probe"), "git": str(self.cwd / ".git/write-probe"), "external": str(self.source / "write-probe")}
        code += "for k,p in " + repr(write_paths) + ".items():\n try: pathlib.Path(p).write_text('fixture');r[k]='WRITABLE'\n except OSError:r[k]='DENIED'\nprint(json.dumps(r))"
        result = self.exec(server, code)
        self.assertEqual(result, {"source": "READABLE", "auth": "DENIED", "controller": "DENIED", "original": "DENIED",
                                  "edit": "WRITABLE", "git": "DENIED", "external": "DENIED"})

    def test_native_shell_disables_incidental_python_bytecode(self):
        server = self.server(False)
        result = self.exec(server, "import os,json;print(json.dumps({'bytecode':os.environ.get('PYTHONDONTWRITEBYTECODE')}))")
        self.assertEqual(result, {"bytecode": "1"})

    def test_reviewer_official_permissions_deny_code_edits(self):
        server = self.server(True)
        paths = {"source": str(self.cwd / "score.py"), "auth": str(self.auth / "private-sentinel"),
                 "controller": str(self.root / "state/control/private-sentinel"), "original": str(self.source / "score.py")}
        code = "import pathlib,json\nr={}\nfor k,p in " + repr(paths) + ".items():\n try: pathlib.Path(p).read_bytes();r[k]='READABLE'\n except OSError:r[k]='DENIED'\ntry: pathlib.Path('score.py').write_text('bad');r['edit']='WRITABLE'\nexcept OSError:r['edit']='DENIED'\nprint(json.dumps(r))"
        self.assertEqual(self.exec(server, code), {"source": "READABLE", "auth": "DENIED", "controller": "DENIED", "original": "DENIED", "edit": "DENIED"})

    def test_operator_mcp_and_hooks_cannot_expand_execution_authority(self):
        marker = self.root / "mcp-must-not-run"
        (self.auth / "config.toml").write_text('[mcp_servers.unapproved]\ncommand="/bin/sh"\nargs=["-c", "touch ' + str(marker) + '"]\n[features]\nhooks=true\n')
        server = self.server(False)
        # config/read is safe here: this isolated smoke home has no real secrets.
        effective = server._request("config/read", {"includeLayers": False})["config"]
        self.assertTrue(all(not server.get("enabled", True) for server in effective.get("mcp_servers", {}).values()))
        self.assertFalse(effective.get("features", {}).get("hooks"))
        self.assertFalse(marker.exists())

    def test_untrusted_parent_mcp_layers_remain_disabled_with_valid_transports(self):
        marker = self.root / "parent-mcp-must-not-run"
        parent_config = self.root / ".codex"
        parent_config.mkdir()
        (parent_config / "config.toml").write_text(
            '[mcp_servers.parent_stdio]\ncommand="/bin/sh"\n'
            'args=["-c", "touch ' + str(marker) + '"]\n'
            '[mcp_servers.parent_http]\nurl="http://127.0.0.1:1/mcp"\n'
        )
        server = self.server(False)
        effective = server._request("config/read", {"includeLayers": False})["config"]
        for name in ("parent_stdio", "parent_http"):
            self.assertFalse(effective["mcp_servers"][name]["enabled"])
        self.assertFalse(marker.exists())
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))

    def test_existing_bubblewrap_gate_runs_exact_commit_and_denies_source_mutation(self):
        target = self.factory.target(self.spec, self.cwd)
        result = LocalRuntime().gate(["python3", "-c", "from score import add; assert add(2,3)==5"], self.cwd,
                                     target, self.root / "gate.raw", 30)
        self.assertEqual(result["status"], "PASS", result)
        blocked = LocalRuntime().gate(["python3", "-c", "open('score.py','w').write('bad')"], self.cwd,
                                      target, self.root / "gate-denied.raw", 30)
        self.assertEqual(blocked["status"], "FAIL")
        self.assertEqual(self.factory.target(self.spec, self.cwd), target)

    def test_runtime_watchdog_expires_without_controller_reads_or_model_inference(self):
        server = FactoryAppServer({"provider": "openai", "model": "offline-protocol-no-inference", "codex_home": str(self.auth)},
                                  self.cwd, self.root / "watchdog.raw", 1, [self.root / "state", self.source], True)
        self.addCleanup(server.close)
        code = server.proc.wait(timeout=3)
        self.assertNotEqual(code, 0)
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))


if __name__ == "__main__":
    unittest.main()

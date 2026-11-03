"""Installed official runtime compatibility, with zero model inference requests."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness.appserver_process import AppServerProcess, process_identity
from harness.factory import Factory, git
from harness.codex import AppServerCodex
from harness.factory_budget import planning_limits
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

    def server(self, read_only, token_limit=None, timeout=30, reuse_session=False, **selection):
        server = FactoryAppServer({"provider": "openai", "model": "offline-protocol-no-inference", "codex_home": str(self.auth), **selection},
                                  self.cwd, self.root / ("review.raw" if read_only else "develop.raw"),
                                  timeout, [self.root / "state", self.source], read_only, read_only, token_limit)
        self.addCleanup(server.close)
        server._reuse_session = reuse_session
        server.start_or_resume(None, str(self.cwd))
        self.assertEqual(server.runtime_identity["provider"], "openai")
        return server

    def test_stronger_model_and_high_effort_bind_start_and_same_thread_resume_without_inference(self):
        server = self.server(False, 120000, reuse_session=True, model="gpt-6.1-sol", effort="high")
        # start_or_resume returns the native thread ID; thread/start itself is
        # metadata configuration and does not establish inference entitlement.
        thread_id = next(e["result"]["thread"]["id"] for e in server.events
                         if "result" in e and "thread" in e["result"])
        server._request("thread/inject_items", {"threadId": thread_id, "items": [
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "offline synthetic history; no inference"}]}]})
        server.token_limit = 36000
        self.assertEqual(server.start_or_resume(thread_id, str(self.cwd)), thread_id)
        self.assertEqual(server.runtime_identity["model"], "gpt-6.1-sol")
        self.assertEqual(server.runtime_identity["effort"], "high")
        effective = server._request("config/read", {"includeLayers": False})["config"]
        self.assertEqual(effective["model"], "gpt-6.1-sol")
        self.assertEqual(effective["model_reasoning_effort"], "high")
        # config/read describes process configuration, not resumed-thread
        # overrides. Assert the submitted stage cap without claiming a physical
        # provider cap or inference access from metadata alone.
        self.assertEqual(server._thread_policy_params(str(self.cwd))["config"]["features"]["rollout_budget"]["limit_tokens"], 36000)
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))

    def test_developer_cannot_edit_controller_scope_without_inference(self):
        scope = self.cwd / "mission-scope.json"
        scope.write_text('{"controller":"owned"}\n')
        server = FactoryAppServer({"provider": "openai", "model": "offline-protocol-no-inference",
            "codex_home": str(self.auth)}, self.cwd, self.root / "scope.raw", 30,
            [self.root / "state", self.source], False, protected_paths=(scope,))
        self.addCleanup(server.close)
        server.start_or_resume(None, str(self.cwd))
        result = self.exec(server, "import pathlib,json\np=pathlib.Path('mission-scope.json')\n"
            "r={'readable':p.read_text()}\n"
            "try:p.write_text('changed');r['write']='WRITABLE'\n"
            "except OSError:r['write']='DENIED'\nprint(json.dumps(r))")
        self.assertEqual(result, {"readable": '{"controller":"owned"}\n', "write": "DENIED"})

    def test_same_thread_resume_applies_overrides_after_unsubscribe_without_inference(self):
        server = self.server(False, 120000, reuse_session=True,
                             model="gpt-6.1-sol", effort="high")
        thread_id = next(e["result"]["thread"]["id"] for e in server.events
                         if "thread" in e.get("result", {}))
        server._request("thread/inject_items", {"threadId": thread_id, "items": [
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "offline resume configuration regression"}]}]})
        server.token_limit = 36000
        # Effort is an observable witness that resume config was applied. No
        # model turn runs; production still pins the authorized effort unchanged.
        server.REASONING_EFFORT = "low"
        original = server._thread_policy_params
        def policy(cwd):
            params = original(cwd)
            params["config"]["model_reasoning_effort"] = "low"
            return params
        with patch.object(server, "_thread_policy_params", side_effect=policy):
            # Negative control: bypass the Factory unsubscribe fix.
            with self.assertRaisesRegex(RuntimeError, "different configured reasoning effort"):
                AppServerCodex.start_or_resume(server, thread_id, str(self.cwd))
            self.assertEqual(server.runtime_identity["effort"], "high")
            self.assertEqual(server.start_or_resume(thread_id, str(self.cwd)), thread_id)
        self.assertEqual(server.runtime_identity["effort"], "low")
        self.assertEqual(self.exec(server, "import json;from score import add;print(json.dumps(add(2,3)))"), 5)
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))

    def test_ephemeral_history_cannot_resume_for_repair_without_inference(self):
        server = self.server(False)
        thread_id = next(e["result"]["thread"]["id"] for e in server.events
                         if "result" in e and "thread" in e["result"])
        server._request("thread/inject_items", {"threadId": thread_id, "items": [
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "offline synthetic ephemeral history"}]}]})
        with self.assertRaisesRegex(RuntimeError, "no rollout found"):
            server.start_or_resume(thread_id, str(self.cwd))
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))

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

    def test_native_official_transport_disables_ambiguous_retries(self):
        server = self.server(True)
        effective = server._request("config/read", {"includeLayers": False})["config"]
        transport = effective["model_providers"][server._transport_provider]
        self.assertEqual(transport["name"], "OpenAI")
        self.assertTrue(transport["requires_openai_auth"])
        self.assertEqual(transport["request_max_retries"], 0)
        self.assertEqual(transport["stream_max_retries"], 0)
        self.assertFalse(transport["supports_websockets"])
        self.assertFalse(transport.get("base_url"))
        identity = server.runtime_identity
        self.assertEqual(identity["route_identity"]["codex_home"], str(self.auth))
        self.assertEqual(identity["route_identity"]["requested_model"], "offline-protocol-no-inference")
        self.assertEqual(identity["reported_model"], "offline-protocol-no-inference")
        self.assertEqual(identity["model_identity_source"], "official_app_server_thread_model_and_reroute_events")
        self.assertEqual(len(identity["qualification_identity"]), 64)
        for feature in ("unbounded_connection_retries", "responses_websockets", "responses_websockets_v2"):
            self.assertFalse(effective["features"][feature])
        self.assertFalse(effective["agents"]["enabled"])
        self.assertEqual(server._thread_policy_params(str(self.cwd))["config"]["agents"], {"enabled": False})
        self.assertEqual(server.runtime_identity["transport_provider"], server._transport_provider)
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))

    def test_installed_native_delegation_switch_at_both_layers_without_a_turn(self):
        server = FactoryAppServer({"provider": "openai", "model": "offline-protocol-no-inference", "codex_home": str(self.auth)},
                                  self.cwd, self.root / "delegation-control.raw", 30,
                                  [self.root / "state", self.source], True, True)
        self.addCleanup(server.close)
        effective = server._request("config/read", {"includeLayers": False})["config"]
        self.assertFalse(effective["agents"]["enabled"])
        self.assertEqual(server._thread_policy_params(str(self.cwd))["config"]["agents"], {"enabled": False})
        self.assertFalse(any(e.get("method") in ("turn/started", "thread/started") for e in server.events))

    def test_native_shell_disables_incidental_python_bytecode(self):
        server = self.server(False)
        result = self.exec(server, "import os,json;print(json.dumps({'bytecode':os.environ.get('PYTHONDONTWRITEBYTECODE')}))")
        self.assertEqual(result, {"bytecode": "1"})

    def test_agent_cannot_connect_host_docker_socket_without_inference(self):
        # Connect-only probe, never a Docker request or daemon operation.
        server = self.server(False)
        code = ("import socket,json\nr={}\n"
                "for path in ['/var/run/docker.sock','/run/docker.sock']:\n"
                " s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
                " try: s.connect(path);r[path]='CONNECTED'\n"
                " except OSError:r[path]='DENIED'\n"
                " finally:s.close()\n"
                "print(json.dumps(r))")
        self.assertEqual(self.exec(server, code), {"/var/run/docker.sock":"DENIED", "/run/docker.sock":"DENIED"})

    def test_installed_native_planning_budget_is_configured_without_inference(self):
        limits = planning_limits({"max_run_tokens": 240000}, 900)
        server = self.server(True, limits["max_tokens"], limits["timeout_seconds"])
        effective = server._request("config/read", {"includeLayers": False})["config"]
        native = effective["features"]["rollout_budget"]
        self.assertTrue(native["enabled"])
        self.assertEqual(native["limit_tokens"], 32000)
        self.assertEqual(native["sampling_token_weight"], 1.0)
        self.assertEqual(native["prefill_token_weight"], 1.0)
        self.assertEqual(server.runtime_identity["native_runtime"]["execution_limits"],
                         {"token_limit": 32000, "timeout_seconds": 120, "physical_token_ceiling": "NOT_GUARANTEED"})
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))

    def test_stage_budget_is_sent_when_starting_or_resuming_same_thread(self):
        server = self.server(True, 60000)
        first = server._thread_policy_params(str(self.cwd))["config"]["features"]["rollout_budget"]
        self.assertEqual(first["limit_tokens"], 60000)
        server.token_limit = 36000
        repair = server._thread_policy_params(str(self.cwd))["config"]["features"]["rollout_budget"]
        self.assertEqual(repair["limit_tokens"], 36000)
        self.assertEqual(repair["sampling_token_weight"], 1.0)
        self.assertEqual(repair["prefill_token_weight"], 1.0)

    def test_efficiency_guidance_preserves_native_repository_instruction_loading(self):
        instructions = self.cwd / "AGENTS.md"
        instructions.write_text("# Repository policy\nNever bypass regression tests or independent QA.\n")
        server = self.server(False)
        result = next(e["result"] for e in server.events
                      if isinstance(e.get("result"), dict) and "thread" in e["result"])
        self.assertIn(str(instructions), result["instructionSources"])
        params = server._thread_policy_params(str(self.cwd))
        self.assertNotIn("baseInstructions", params)
        self.assertNotIn("project_doc_max_bytes", params["config"])
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))

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
        initialized, reader_paused, resume_reads = (threading.Event() for _ in range(3))
        streams = []
        start = AppServerProcess.start

        def capture(owner, argv, **kwargs):
            proc = start(owner, argv, **kwargs)
            streams.extend((proc.stdin, proc.stdout))
            stdout = proc.stdout

            def read_line():
                if initialized.is_set():
                    reader_paused.set()
                    resume_reads.wait()
                line = stdout.readline()
                if line and json.loads(line).get("id") == 1:
                    initialized.set()
                return line

            # Forward real I/O; audit every outgoing message and stop draining
            # stdout after the initialize response, before waiting for expiry.
            proc.stdin = Mock(wraps=proc.stdin)
            proc.stdout = Mock(wraps=stdout)
            proc.stdout.readline.side_effect = read_line
            return proc

        self.addCleanup(resume_reads.set)
        with patch.object(AppServerProcess, "start", capture):
            server = FactoryAppServer({"provider": "openai", "model": "offline-protocol-no-inference", "codex_home": str(self.auth)},
                                      self.cwd, self.root / "watchdog.raw", 1, [self.root / "state", self.source], True)
        self.addCleanup(server.close)
        self.addCleanup(resume_reads.set)
        owner = server._execution
        payload = owner.payload
        self.assertTrue(reader_paused.wait(timeout=1))
        self.assertNotIn(process_identity(payload["pid"])["state"], ("Z", "X"))
        deadline = time.monotonic() + 3
        while process_identity(payload["pid"])["state"] not in ("Z", "X"):
            self.assertLess(time.monotonic(), deadline, "watchdog payload did not expire autonomously")
            time.sleep(.01)
        # Observe autonomous completion BEFORE stop/close. The supervisor is
        # still the unreaped ownership anchor, not the timeout payload.
        self.assertFalse(resume_reads.is_set())
        self.assertEqual(process_identity(payload["pid"])["starttime"], payload["starttime"])
        self.assertNotIn(process_identity(server.proc.pid)["state"], ("Z", "X"))
        self.assertIsNone(server.proc.returncode)
        self.assertIsNone(owner.stopped)
        self.assertIsNone(owner.failure)
        resume_reads.set()
        server.close()
        stop = server._process_stop
        self.assertTrue(stop["confirmed"])
        self.assertEqual(stop["proof"], "ECHILD")
        self.assertEqual(stop["binding"], owner.binding)
        self.assertEqual(stop["signals"], [], "close must not cause the observed timeout exit")
        status = next(v["status"] for v in stop["reaped"] if v["pid"] == payload["pid"])
        self.assertEqual(os.waitstatus_to_exitcode(status), 124)
        self.assertEqual(server.proc.returncode, 0)
        self.assertFalse(Path(f"/proc/{server.proc.pid}").exists())
        self.assertTrue(all(not Path(f'/proc/{v["pid"]}').exists() for v in stop["reaped"]))
        self.assertIsNone(owner.pidfd)
        self.assertEqual(owner.channel.fileno(), -1)
        self.assertTrue(all(stream.closed for stream in streams))
        self.assertIsNone(server._task_temp)
        self.assertFalse(list(self.root.glob("*.temp.json")))
        messages = [json.loads(call.args[0]) for call in server.proc.stdin.write.call_args_list]
        self.assertEqual([message["method"] for message in messages], ["initialize", "initialized"])
        self.assertFalse(any(e.get("method") == "turn/started" for e in server.events))


if __name__ == "__main__":
    unittest.main()

"""Transport contracts exercised against real local HTTP, with no paid calls."""
import base64
import copy
import http.server
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from harness.factory import Factory, FactoryBlocked, git, validate_config
from harness.factory_cli import main as factory_cli
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_proxy import (
    LEGACY_PROXY_IMAGE, LEGACY_PROXY_IMAGES, PROXY_TMPFS_OPTIONS, PROXY_V8_0_77_IMAGE, PROXY_V8_0_77_IMAGES,
    SNAPSHOT_REJECTED, ProxyPolicy, ProxyRelay, snapshot_identity, validate_transport, verify_snapshot_expiry,
)
from harness.factory_runtime import FactoryAppServer, LocalRuntime, RuntimeFailure
from scripts.configure_factory_proxy import managed_config, managed_credential, verify_release
from test_factory_routing import pool


class ProxyContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = "not-a-real-proxy-credential-sentinel"
        self.management_key = "not-a-real-management-credential-sentinel"
        self.requests = []
        self.telemetry = []
        self.mode = "complete"
        fixture = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                if self.path.endswith("request-retry"):
                    value = {"request-retry": 0}
                elif self.path.endswith("max-retry-credentials"):
                    value = {"max-retry-credentials": 1}
                else:
                    value, fixture.telemetry = fixture.telemetry, []
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(value).encode())
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fixture.requests.append({"body": body, "auth": self.headers.get("Authorization")})
                if fixture.mode == "http_error":
                    self.send_error(500, fixture.key)
                    return
                if fixture.mode == "unauthorized":
                    self.send_error(401, fixture.key)
                    return
                if fixture.mode in {"stream_unauthorized", "stream_status_401"}:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    failed = {"type": "response.failed", "response": {
                        "error": {**({"code": 401} if fixture.mode == "stream_status_401"
                                     else {"code": "invalid_api_key"}), "message": fixture.key},
                    }}
                    self.wfile.write(b"data: " + json.dumps(failed).encode() + b"\n\n")
                    return
                if fixture.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "https://api.openai.com/v1/responses")
                    self.end_headers()
                    return
                model = "different-model" if fixture.mode == "model_mismatch" else body["model"]
                status = "incomplete" if fixture.mode == "partial" else "completed"
                terminal = {"type": "response."+status,
                            "response": {"id": "resp_fixture", "model": model, "status": status,
                                         "usage": {"input_tokens": 10, "output_tokens": 3, "total_tokens": 13}}}
                fixture.telemetry.append({"provider": "codex", "executor_type": "CodexExecutor", "model": body["model"], "response_model": model,
                                          "session_id": self.headers["Session_id"], "request_id": "proxy-request-fixture", "execution_id": "execution-fixture",
                                          "tokens": {"input_tokens": 10, "output_tokens": 3, "total_tokens": 13}, "failed": status != "completed",
                                          "api_key": fixture.key, "source": "private-account-name", "fail": {"body": fixture.management_key},
                                          "response_headers": {"Set-Cookie": "private-cookie"}})
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b"data: "+json.dumps(terminal).encode()+b"\n\n")
        self.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.upstream.daemon_threads = True
        self.thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        self.endpoint = f"http://127.0.0.1:{self.upstream.server_port}/v1"
        auth_dir = self.root / "auth"
        auth_dir.mkdir(mode=0o700)
        self.auth = auth_dir / "codex.json"
        self.write(self.auth, json.dumps({"type": "codex", "access_token": "fake-oauth", "request_retry": 0, "websockets": False}))
        self.config_path = self.root / "proxy.json"
        self.config = managed_config(self.key, self.management_key, "http://127.0.0.1:7897")
        self.write(self.config_path, json.dumps(self.config))
        for name, value in (("key", self.key), ("management", self.management_key)):
            self.write(self.root/name, value)
        self.policy_file = self.root / "policy.json"
        self.image = LEGACY_PROXY_IMAGE
        self.write(self.policy_file, json.dumps({"version": 1, "container": "fixture-container", "image": self.image, "endpoint": self.endpoint,
                   "config_file": str(self.config_path), "auth_file": str(self.auth), "credential_file": str(self.root/"key"), "management_token_file": str(self.root/"management")}))
        self.transport = {"type": "cli_proxy", "endpoint": self.endpoint, "configured_provider": "cli_proxy_api", "policy_file": str(self.policy_file)}
        self.profile = {"provider": "openai", "model": "fixture-model", "transport": self.transport}
        mounts = {"/CLIProxyAPI/config.yaml": str(self.config_path), "/factory-auth": str(auth_dir)}
        self.container = {"Id": "runtime-fixture", "Image": self.image, "State": {"Running": True},
                          "Config": {"Entrypoint": None, "WorkingDir": "/CLIProxyAPI",
                                     "Cmd": ["/CLIProxyAPI/CLIProxyAPI", "-config", "/CLIProxyAPI/config.yaml", "-local-model"]},
                          "HostConfig": {"ReadonlyRootfs": True,
                                         "PortBindings": {"8317/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(self.upstream.server_port)}]},
                                         "Mounts": [{"Type": "bind", "Target": target, "Source": source, "ReadOnly": True,
                                                     "BindOptions": {"NonRecursive": True, "Propagation": "rprivate"}}
                                                    for target, source in mounts.items()]},
                          "Mounts": [{"Type": "bind", "Destination": target, "Source": source, "RW": False,
                                      "Propagation": "rprivate"} for target, source in mounts.items()]}
        self.inspect = patch("harness.factory_proxy.docker_json", return_value=[self.container])
        self.inspect.start()
        self.addCleanup(self.inspect.stop)

    @staticmethod
    def write(path, value):
        path.write_text(value)
        path.chmod(0o600)

    def relay(self):
        relay = ProxyRelay(self.profile, self.root / "run.raw", 5)
        self.addCleanup(relay.close)
        return relay

    def use_image(self, image):
        policy = json.loads(self.policy_file.read_text())
        policy["image"] = self.container["Image"] = image
        self.write(self.policy_file, json.dumps(policy))
        config = managed_config(self.key, self.management_key, "http://127.0.0.1:7897", image)
        self.write(self.config_path, json.dumps(config))
        auth = json.loads(self.auth.read_text())
        auth["expired"] = "2100-01-01T00:00:00Z"
        self.write(self.auth, json.dumps(auth))
        if image in PROXY_V8_0_77_IMAGES:
            self.pin_snapshot()
        else:
            self.transport.pop("snapshot_id", None)
        return config

    def pin_snapshot(self):
        self.transport["snapshot_id"] = snapshot_identity(self.management_key, self.auth.read_bytes())

    def post(self, relay, model="fixture-model"):
        request = urllib.request.Request(relay.base_url+"/responses", data=json.dumps({"model": model, "stream": True}).encode(),
                                         headers={"Authorization": "Bearer "+relay.nonce})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            exc.close()
            return b""

    def test_schema_keeps_legacy_official_and_explicit_lanes_separate(self):
        config = fixture_config()
        self.assertEqual(validate_transport(config["profiles"]["developer"]), {"type": "official"})
        config["profiles"]["developer"] = self.profile
        self.assertEqual(validate_config(config)["profiles"]["developer"]["transport"], self.transport)
        config["profiles"]["reviewer"] = self.profile
        with self.assertRaisesRegex(ValueError, "REVIEWER_NOT_QUALIFIED"):
            validate_config(config)
        config = fixture_config()
        config["profiles"]["second_reviewer"]["transport"] = self.transport
        with self.assertRaisesRegex(ValueError, "DeepSeek.*direct"):
            validate_config(config)
        for transport in ({"type": "auto"}, {"type": "official", "endpoint": self.endpoint}, {**self.transport, "endpoint": "http://user:secret@127.0.0.1:9/v1"}, {**self.transport, "fallback": "official"}):
            with self.assertRaises(ValueError):
                validate_transport({**self.profile, "transport": transport})

    def test_managed_policy_rejects_retries_aliases_multiple_credentials_and_runtime_changes(self):
        for mutate in (lambda c: c["routing"]["retry"].update({"request-retry": 3}),
                       lambda c: c["requests"]["streaming"].update({"bootstrap-retries": 1}),
                       lambda c: c["oauth"].update({"model-alias": {"codex": []}})):
            config = copy.deepcopy(self.config)
            mutate(config)
            self.write(self.config_path, json.dumps(config))
            with self.assertRaises(ValueError):
                ProxyPolicy(self.transport)
        self.write(self.config_path, json.dumps(self.config))
        self.write(self.auth.parent/"extra.json", "{}")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            ProxyPolicy(self.transport)
        (self.auth.parent/"extra.json").unlink()
        self.container["Image"] = "different-image"
        with self.assertRaisesRegex(ValueError, "runtime identity"):
            ProxyPolicy(self.transport)

    def test_provisioning_requires_matching_release_and_image(self):
        legacy = "CLIProxyAPI Version: v8.0.15, Commit: a4acc9f, BuiltAt: fixture"
        modern = "CLIProxyAPI Version: v8.0.77, Commit: a5e8f69e, BuiltAt: fixture"
        for release_images, banner in ((LEGACY_PROXY_IMAGES, legacy), (PROXY_V8_0_77_IMAGES, modern)):
            for image in release_images:
                with self.subTest(image=image):
                    verify_release(image, banner)
                    self.use_image(image)
                    self.assertEqual(ProxyPolicy(self.transport).identity["image"], image)
        for image, banner in (
            (LEGACY_PROXY_IMAGE, modern),
            (PROXY_V8_0_77_IMAGE, legacy),
            (PROXY_V8_0_77_IMAGE, modern.replace("v8.0.77", "v8.0.78")),
            (PROXY_V8_0_77_IMAGE, modern.replace("a5e8f69e", "a5e8f69f")),
            ("sha256:" + "f" * 64, modern),
        ):
            with self.subTest(image=image, banner=banner), self.assertRaises(ValueError):
                verify_release(image, banner)

    def test_v8_0_77_policy_checks_layout_and_isolation(self):
        config = self.use_image(PROXY_V8_0_77_IMAGE)
        self.assertEqual(config["multimedia"], {"disable-image-generation": True})
        self.assertEqual(config["observability"]["logs"]["request-log"], False)
        self.assertEqual(ProxyPolicy(self.transport).identity["image"], PROXY_V8_0_77_IMAGE)
        for invalid in (self.config, {**config, "multimedia": {}},
                        {**config, "observability": self.config["observability"]}):
            self.write(self.config_path, json.dumps(invalid))
            with self.assertRaises(ValueError):
                ProxyPolicy(self.transport)
        self.write(self.config_path, json.dumps(config))
        with patch.object(ProxyPolicy, "management", return_value={"request-retry": 1}):
            with self.assertRaisesRegex(ValueError, "running proxy retry policy"):
                ProxyPolicy(self.transport)
        extra = self.auth.parent / "other.json"
        self.write(extra, "{}")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            ProxyPolicy(self.transport)
        extra.unlink()
        for mount in self.container["Mounts"]:
            with self.subTest(mount=mount["Destination"]):
                mount["RW"] = True
                with self.assertRaisesRegex(ValueError, "mounts must be pinned read-only"):
                    ProxyPolicy(self.transport)
                mount["RW"] = False
        policy = json.loads(self.policy_file.read_text())
        policy["image"] = self.container["Image"] = "sha256:" + "f" * 64
        self.write(self.policy_file, json.dumps(policy))
        with self.assertRaisesRegex(ValueError, "not a supported release"):
            ProxyPolicy(self.transport)

    def test_only_the_expected_mounts_and_tmpfs_are_accepted(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        self.container["HostConfig"]["Tmpfs"] = {"/tmp": "rw,noexec,nosuid,size=32m"}
        ProxyPolicy(self.transport)
        self.container["Mounts"].append({"Type": "tmpfs", "Destination": "/tmp", "RW": True})
        ProxyPolicy(self.transport)
        self.container["HostConfig"]["Tmpfs"]["/tmp"] = PROXY_TMPFS_OPTIONS
        ProxyPolicy(self.transport)
        for mount_type, path in (
            ("volume", "/CLIProxyAPI"),
            ("volume", "/factory-auth/logs"),
            ("tmpfs", "/factory-auth"),
            ("bind", "/CLIProxyAPI/CLIProxyAPI"),
        ):
            with self.subTest(mount_type=mount_type, path=path):
                self.container["Mounts"].append({"Type": mount_type, "Destination": path, "RW": True})
                with self.assertRaisesRegex(ValueError, "mount"):
                    ProxyPolicy(self.transport)
                self.container["Mounts"].pop()
        self.container["HostConfig"]["Tmpfs"]["/CLIProxyAPI"] = "rw"
        with self.assertRaisesRegex(ValueError, "unexpected mount"):
            ProxyPolicy(self.transport)

    def test_rejects_unproven_mount_metadata(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        baseline = copy.deepcopy(self.container)
        host = self.container["HostConfig"]
        for mutate in (
            lambda: host.update(Mounts=[]),
            lambda: host.update(Binds=["/fixture:/factory-auth:rw"]),
            lambda: host.update(VolumesFrom=["other"]),
            lambda: host["Mounts"].append({"Type": "tmpfs", "Target": "/factory-auth"}),
            lambda: host["Mounts"][1].update(ReadOnly=False),
            lambda: host["Mounts"][1]["BindOptions"].update(ReadOnlyNonRecursive=True),
            lambda: host["Mounts"][1]["BindOptions"].update(NonRecursive=False),
            lambda: host["Mounts"][1]["BindOptions"].update(ReadOnlyForceRecursive=True),
            lambda: host["Mounts"][1]["BindOptions"].update(Propagation="rshared"),
            lambda: self.container["Mounts"][1].update(Propagation="rslave"),
            lambda: self.container["Config"].update(WorkingDir="/tmp"),
            *(lambda option=option: host.update(Tmpfs={"/tmp": PROXY_TMPFS_OPTIONS + "," + option})
              for option in ("exec", "suid", "dev", "size=64m")),
        ):
            mutate()
            with self.assertRaisesRegex(ValueError, "mount|working directory"):
                ProxyPolicy(self.transport)
            self.container.update(copy.deepcopy(baseline))
            host = self.container["HostConfig"]
        host["Mounts"][1]["BindOptions"] = {"ReadOnlyForceRecursive": True, "Propagation": "rprivate"}
        ProxyPolicy(self.transport)

    def test_snapshot_pin_is_required_and_changes_with_exact_bytes(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        approved = dict(self.transport)
        ProxyPolicy(approved)
        self.transport.pop("snapshot_id")
        with self.assertRaisesRegex(ValueError, "SNAPSHOT_AUTHORIZATION_REQUIRED"):
            ProxyPolicy(self.transport)
        self.write(self.auth, self.auth.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "SNAPSHOT_CHANGED"):
            ProxyPolicy(approved)
        self.pin_snapshot()
        ProxyPolicy(self.transport)

    def test_v8_0_77_provisions_no_refresh_material_and_rejects_expired_or_unknown_expiry(self):
        source = {"type": "codex", "access_token": "offline-token", "refresh_token": "legacy-refresh",
                  "siwc": {"refresh_token": "nested-refresh"}, "expired": "2100-01-01T00:00:00Z"}
        self.assertEqual(managed_credential(source, LEGACY_PROXY_IMAGE)["refresh_token"], "legacy-refresh")
        snapshot = managed_credential(source, PROXY_V8_0_77_IMAGE)
        self.assertEqual(snapshot["access_token"], source["access_token"])
        self.assertNotIn("refresh_token", snapshot)
        self.assertNotIn("siwc", snapshot)
        self.assertEqual(source["refresh_token"], "legacy-refresh")
        self.use_image(PROXY_V8_0_77_IMAGE)
        for key in ("refresh_token", "refreshToken", "siwc"):
            self.write(self.auth, json.dumps({**snapshot, key: source["refresh_token"]}))
            self.pin_snapshot()
            with self.assertRaisesRegex(ValueError, "credential aliases"):
                ProxyPolicy(self.transport)
        for values, reason in (
            ({"access_token": "opaque"}, "EXPIRY_UNKNOWN"),
            ({"access_token": "opaque", "expired": "2100-01-01"}, "EXPIRY_UNKNOWN"),
            ({"access_token": "opaque", "expired": "2000-01-01T00:00:00Z"}, "SNAPSHOT_EXPIRED"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                managed_credential(values, PROXY_V8_0_77_IMAGE)
        exp = base64.urlsafe_b64encode(b'{"exp":1}').decode().rstrip("=")
        with self.assertRaisesRegex(ValueError, "SNAPSHOT_EXPIRED"):
            verify_snapshot_expiry({**snapshot, "access_token": f"header.{exp}.signature"})

    def test_v8_0_77_expiry_is_rechecked_before_forwarding(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        relay = self.relay()
        with patch("harness.factory_proxy.time.time", return_value=4102444800):
            self.post(relay)
        self.post(relay)
        self.assertEqual(self.requests, [])
        self.assertIn("CLI_PROXY_SNAPSHOT_EXPIRED", relay.receipt()["stop_reason"])
        self.assertEqual(relay.receipt()["physical_attempts"], [])
        with self.assertRaisesRegex(ValueError, "SNAPSHOT_EXPIRED"):
            relay.start_turn(self.root / "another.raw", 5, None)

    def test_v8_0_77_snapshot_cannot_be_replaced_mid_session(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        relay = self.relay()
        auth = json.loads(self.auth.read_text())
        auth["access_token"] = "offline-replacement"
        self.write(self.auth, json.dumps(auth))
        self.post(relay)
        self.assertEqual(self.requests, [])
        self.assertIn("CLI_PROXY_SNAPSHOT_CHANGED", relay.receipt()["stop_reason"])

    def task_config(self, routed):
        config = fixture_config()
        config.update(simulation=False, review_mode="single_openai",
                      budget={"max_agent_runs": 5, "max_run_tokens": 100, "max_total_tokens": 500})
        config["profiles"]["developer"] = copy.deepcopy(self.profile)
        config["profiles"].pop("second_reviewer")
        if routed:
            config["model_routing"] = pool()
            for entry in config["model_routing"]["models"]:
                entry["transport"] = dict(self.transport)
        return config

    def replace_snapshot(self, account_changed):
        auth = json.loads(self.auth.read_text())
        auth["access_token"] = "replacement-fixture-token"
        if account_changed:
            auth["account_id"] = "replacement-fixture-account"
        self.write(self.auth, json.dumps(auth))

    def test_task_dispatch_binds_the_exact_snapshot_across_sqlite_reopen(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        source = self.root / "source"
        source.mkdir()
        git(source, "init", "-q")
        git(source, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit",
            "--allow-empty", "-qm", "baseline")
        auth = json.loads(self.auth.read_text())
        auth["account_id"] = "approved-fixture-account"
        original = json.dumps(auth)

        def open_factory(name, config):
            runtime = LocalRuntime()
            live_identity = runtime.profile_identity
            # Developer policy and task routing are real. The reviewer lane
            # is unused here and never reads a real Codex home.
            runtime.profile_identity = lambda profile: (
                live_identity(profile) if profile.get("transport", {}).get("type") == "cli_proxy"
                else {"configured": profile})
            return Factory(self.root / name, config, runtime)

        def appserver(profile, cwd, transcript, timeout, denied_roots, readonly, review, token_limit, **_):
            # Substitute the native model process only. Loopback uses the
            # production relay and its real pre-forward Docker policy check.
            relay = ProxyRelay(profile, transcript, timeout, token_limit)
            server = Mock(_proxy_relay=relay, _task_temp=None, runtime_identity=None)
            server.usage_telemetry.return_value = None
            server.close.side_effect = relay.close

            def execute(prompt, schema, **_):
                self.assertNotIn("snapshot_id", prompt)
                if scenario == "after_relay":
                    self.replace_snapshot(False)
                body = self.post(relay, profile["model"])
                relay.collect_telemetry()
                if not body:
                    self.assertIn("SNAPSHOT_CHANGED", relay.receipt()["stop_reason"])
                    raise RuntimeFailure("synthetic turn stopped")
                route = {**relay.policy.transport, "route_type": "cli_proxy",
                         "auth_source": relay.policy.policy["credential_file"],
                         "requested_model": profile["model"], "runtime": relay.policy.identity}
                return {"summary": "offline", "usage": relay.usage(), "usage_complete": True,
                        "output": {"plan": "synthetic control", "tasks": [], "acceptance": [],
                                   "decisions_required": ["fixture ends after PLAN"]},
                        "runtime_identity": {"route_identity": route, "reported_model": profile["model"]}}

            server.execute.side_effect = execute
            return server

        for routed in (False, True):
            for scenario in ("unchanged", "different_account", "same_account", "during_construction", "after_relay"):
                with self.subTest(routed=routed, scenario=scenario):
                    state = f"state-{routed}-{scenario}"
                    self.write(self.auth, original)
                    self.pin_snapshot()
                    config = self.task_config(routed)
                    before = len(self.requests)
                    mission = {"version": 2, "mission_id": "snapshot-task", "repository": str(source),
                               "objective": "synthetic snapshot contract"}

                    def construct(*args, **kwargs):
                        if scenario == "during_construction":
                            self.replace_snapshot(False)
                        return appserver(*args, **kwargs)

                    with patch("harness.factory_runtime.AppServerCodex._trusted_executable",
                               return_value=Path("/usr/bin/true")), patch(
                            "harness.factory_preflight.inspect_prepaid", return_value={"findings": []}), patch(
                            "harness.factory_runtime.FactoryAppServer", side_effect=construct) as server:
                        first = open_factory(state, config)
                        try:
                            first.submit(mission)
                            spec = json.loads(first.row("snapshot-task")["spec"])
                            if scenario in {"different_account", "same_account"}:
                                self.replace_snapshot(scenario == "different_account")
                                with self.assertRaisesRegex(ValueError, "SNAPSHOT_CHANGED"):
                                    first.submit({**mission, "mission_id": "another-task"})
                        finally:
                            first.close()
                        reopened = open_factory(state, config)
                        try:
                            if scenario == "unchanged":
                                result = reopened.agent(spec, source, "implement", 1, {})
                                self.assertEqual(result["summary"], "offline")
                                private_evidence = {"executor_identity": reopened.submitted_executor("snapshot-task")}
                                with patch.object(reopened, "_report", return_value={
                                        "LOCAL_CANDIDATE_EVIDENCE": private_evidence}):
                                    report = reopened.report("snapshot-task")
                                self.assertNotIn(self.transport["snapshot_id"], json.dumps(report))
                                self.assertIn(self.transport["snapshot_id"], json.dumps(private_evidence))
                                self.replace_snapshot(False)
                                self.assertEqual(reopened.agent(spec, source, "implement", 1, {}), result)
                                self.assertEqual(server.call_count, 1)
                            else:
                                with self.assertRaisesRegex(FactoryBlocked, "SNAPSHOT_CHANGED"):
                                    reopened.agent(spec, source, "implement", 1, {})
                                rows = reopened.db.execute("SELECT status FROM operations").fetchall()
                                if scenario in {"different_account", "same_account"}:
                                    server.assert_not_called()
                                    self.assertEqual(rows, [])
                                else:
                                    self.assertEqual([row["status"] for row in rows], ["UNKNOWN"])
                        finally:
                            reopened.close()
                        self.assertEqual(len(self.requests) - before, int(scenario == "unchanged"))
                        if scenario in {"unchanged", "same_account", "different_account"}:
                            # Updating the config to match replacement bytes does
                            # not modify the submitted snapshot authorization.
                            self.pin_snapshot()
                            rebound = self.task_config(routed)
                            reopened = open_factory(state, rebound)
                            try:
                                with self.assertRaisesRegex(ValueError, "route changed|immutable mission authority"):
                                    reopened.agent(spec, source, "implement", 2, {})
                            finally:
                                reopened.close()
                            self.assertEqual(len(self.requests) - before, int(scenario == "unchanged"))

        for scenario, expected, forwarded in (
            ("cli_control", "WAITING_PRODUCT_DECISION", 1),
            ("cli_swapped", "BLOCKED_LOCAL_AUTHORITY", 0),
        ):
            with self.subTest(scenario=scenario):
                self.write(self.auth, original)
                self.pin_snapshot()
                config = self.task_config(False)
                config_path = self.root / "cli-config.json"
                self.write(config_path, json.dumps(config))
                mission_path = self.root / "cli-mission.json"
                self.write(mission_path, json.dumps(mission))
                name = scenario
                before = len(self.requests)
                with patch("harness.factory_runtime.AppServerCodex._trusted_executable",
                           return_value=Path("/usr/bin/true")), patch(
                        "harness.factory_preflight.inspect_prepaid", return_value={"findings": []}), patch(
                        "harness.factory_runtime.FactoryAppServer", side_effect=appserver), patch(
                        "harness.factory_cli.Factory", side_effect=lambda _root, cfg, **_: open_factory(name, cfg)):
                    first = open_factory(name, config)
                    try:
                        first.submit(mission)
                    finally:
                        first.close()
                    if scenario == "cli_swapped":
                        self.replace_snapshot(True)
                    with redirect_stdout(io.StringIO()) as report, redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as stopped:
                            factory_cli(["factory-run", str(mission_path), "--config", str(config_path),
                                         "--state-dir", str(self.root / name), "--json"])
                    self.assertEqual(stopped.exception.code, 1)
                    self.assertEqual(json.loads(report.getvalue())["DELIVERY_STATUS"], expected)
                    self.assertNotIn(self.transport["snapshot_id"], report.getvalue())
                    self.assertEqual(len(self.requests) - before, forwarded)

    def test_v8_0_77_unauthorized_latches_transport_without_replay_or_error_body(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        for mode, status in (("unauthorized", 401), ("stream_unauthorized", 200), ("stream_status_401", 200)):
            self.mode = mode
            with self.subTest(mode=mode):
                relay = ProxyRelay(self.profile, self.root / (mode + ".raw"), 5)
                try:
                    before = len(self.requests)
                    body = self.post(relay)
                    self.post(relay)
                    receipt = relay.receipt()
                    self.assertEqual(len(self.requests) - before, 1)
                    self.assertEqual(receipt["stop_reason"], SNAPSHOT_REJECTED)
                    self.assertEqual(receipt["physical_attempts"][0]["proxy_http_status"], status)
                    self.assertEqual(receipt["physical_attempts"][0]["status"], "UNKNOWN")
                    self.assertFalse(receipt["usage_complete"])
                    with self.assertRaisesRegex(ValueError, "SNAPSHOT_REJECTED"):
                        relay.start_turn(self.root / "another.raw", 5, None)
                    self.assertNotIn(self.key, relay.evidence.read_text())
                    self.assertNotIn(self.key.encode(), body)
                finally:
                    relay.close()

    def test_v8_0_77_management_401_is_not_attributed_to_the_access_token(self):
        self.use_image(PROXY_V8_0_77_IMAGE)
        relay = self.relay()
        url = self.endpoint.removesuffix("/v1") + "/v0/management/request-retry"
        error = urllib.error.HTTPError(url, 401, "fixture management rejection", {}, None)
        with patch.object(ProxyPolicy, "management", side_effect=error):
            self.post(relay)
        self.post(relay)
        self.assertTrue(relay.failed)
        self.assertNotIn("stop_reason", relay.receipt())
        self.assertEqual(self.requests, [])

    def test_success_records_physical_requests_actual_model_and_redacted_correlated_telemetry(self):
        relay = self.relay()
        self.post(relay)
        self.post(relay)
        relay.collect_telemetry()
        receipt = relay.receipt()
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(receipt["physical_attempt_count"], 2)
        self.assertEqual(relay.usage()["total_tokens"], 26)
        self.assertTrue(receipt["usage_complete"])
        self.assertEqual(receipt["money"], "UNKNOWN")
        self.assertEqual(receipt["upstream_provider_identity"], "NOT_PROVABLE")
        record = receipt["physical_attempts"][0]
        self.assertEqual(record["reported_model"], "fixture-model")
        self.assertEqual(record["proxy_telemetry"][0]["session_id"], record["http_request_id"])
        self.assertEqual(record["proxy_telemetry"][0]["request_id"], "proxy-request-fixture")
        artifacts = relay.evidence.read_text()+json.dumps(receipt)
        for secret in (self.key, self.management_key, relay.nonce, "private-account-name", "private-cookie"):
            self.assertNotIn(secret, artifacts)
        self.assertEqual(self.requests[0]["auth"], "Bearer "+self.key)

    def test_http_failure_and_redirect_latch_closed_without_replay_or_fallback(self):
        for mode in ("http_error", "redirect"):
            with self.subTest(mode=mode):
                self.mode = mode
                transcript = self.root/(mode+".raw")
                relay = ProxyRelay(self.profile, transcript, 5)
                before = len(self.requests)
                try:
                    self.post(relay)
                    self.post(relay)
                    self.assertEqual(len(self.requests)-before, 1)
                    self.assertFalse(relay.receipt()["usage_complete"])
                    self.assertEqual(relay.receipt()["physical_attempt_count"], "UNKNOWN")
                    self.assertEqual(relay.records[0]["status"], "UNKNOWN")
                    self.assertNotIn(self.key, relay.evidence.read_text())
                finally:
                    relay.close()

    def test_partial_usage_and_wrong_reported_model_fail_closed(self):
        for mode in ("partial", "model_mismatch"):
            with self.subTest(mode=mode):
                self.mode = mode
                relay = ProxyRelay(self.profile, self.root/(mode+".raw"), 5)
                try:
                    self.post(relay)
                    self.assertFalse(relay.receipt()["usage_complete"])
                    self.assertEqual(relay.receipt()["physical_attempt_count"], "UNKNOWN")
                    if mode == "partial":
                        self.assertEqual(relay.usage()["total_tokens"], 13)
                    else:
                        self.assertEqual(relay.records[0]["reported_model"], "different-model")
                finally:
                    relay.close()

    def test_wrong_requested_model_or_policy_drift_never_dispatches(self):
        relay = self.relay()
        self.post(relay, "other-model")
        self.assertEqual(self.requests, [])
        self.assertTrue(relay.failed)
        relay.close()
        # New local test run, not replay of a real unknown upstream request.
        second = ProxyRelay(self.profile, self.root/"drift.raw", 5)
        try:
            self.container["Id"] = "changed-runtime"
            self.post(second)
            self.assertEqual(self.requests, [])
            self.assertTrue(second.failed)
        finally:
            second.close()

    def test_relay_budget_stops_new_http_requests_and_duplicate_attempt_telemetry_is_unknown(self):
        relay = ProxyRelay(self.profile, self.root/"bounded.raw", 5, token_limit=13)
        try:
            self.post(relay)
            self.post(relay)
            self.assertEqual(len(self.requests), 1)
            self.assertEqual(relay.usage()["total_tokens"], 13)
            self.assertFalse(relay.receipt()["usage_complete"])
        finally:
            relay.close()
        duplicate = ProxyRelay(self.profile, self.root/"duplicate.raw", 5)
        try:
            self.post(duplicate)
            self.telemetry.append(dict(self.telemetry[-1], execution_id="second-attempt"))
            duplicate.collect_telemetry()
            self.assertEqual(duplicate.receipt()["physical_attempt_count"], "UNKNOWN")
            self.assertFalse(duplicate.receipt()["usage_complete"])
        finally:
            duplicate.close()

    def test_missing_mismatched_and_unattributed_telemetry_cannot_settle_a_dispatch(self):
        mutations = {
            "missing": lambda rows: rows.clear(),
            "wrong_model": lambda rows: rows[0].update(response_model="other-model"),
            "wrong_provider": lambda rows: rows[0].update(provider="other-provider"),
            "wrong_usage": lambda rows: rows[0]["tokens"].update(input_tokens=99),
            "failed": lambda rows: rows[0].update(failed=True),
            "extra_request": lambda rows: rows.append({"session_id": "unattributed", "api_key": self.key}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                relay = ProxyRelay(self.profile, self.root/(name+".raw"), 5)
                try:
                    self.post(relay)
                    self.assertFalse(relay.receipt()["usage_complete"])
                    mutate(self.telemetry)
                    relay.collect_telemetry()
                    self.assertFalse(relay.receipt()["usage_complete"])
                    self.assertEqual(relay.receipt()["physical_attempt_count"], "UNKNOWN")
                    self.assertEqual(relay.usage()["total_tokens"], 13)
                    count = len(self.requests)
                    self.post(relay)
                    self.assertEqual(len(self.requests), count)
                    self.assertNotIn(self.key, relay.evidence.read_text())
                finally:
                    relay.close()

    def test_repair_rotates_evidence_and_enforces_incremental_observation_limit(self):
        relay = ProxyRelay(self.profile, self.root/"first.raw", 5, token_limit=13)
        try:
            self.post(relay)
            relay.collect_telemetry()
            self.assertTrue(relay.receipt()["usage_complete"])
            first = relay.evidence
            before = hashlib.sha256(first.read_bytes()).hexdigest()
            relay.start_turn(self.root/"repair.raw", 5, 13)
            self.post(relay)
            relay.collect_telemetry()
            self.assertTrue(relay.receipt()["usage_complete"])
            self.assertEqual(relay.usage()["total_tokens"], 26)
            self.assertEqual(len(self.requests), 2)
            self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(), before)
            self.assertNotEqual(first, relay.evidence)
            self.post(relay)
            self.assertEqual(len(self.requests), 2)
            self.assertFalse(relay.receipt()["usage_complete"])
            with self.assertRaisesRegex(ValueError, "uncertain"):
                relay.start_turn(self.root/"forbidden.raw", 5, 100)
        finally:
            relay.close()

    def test_no_http_dispatch_between_completed_turn_and_authorized_repair(self):
        relay = self.relay()
        self.post(relay)
        relay.collect_telemetry()
        self.assertTrue(relay.receipt()["usage_complete"])
        original = relay.evidence.read_bytes()
        self.post(relay)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(relay.evidence.read_bytes(), original)
        self.assertFalse(relay.receipt()["usage_complete"])
        with self.assertRaises(ValueError):
            relay.start_turn(self.root/"unauthorized-repair.raw", 5, 100)

    def test_cached_and_partial_usage_are_preserved_even_on_wrong_model(self):
        relay = self.relay()
        record = {}
        relay.observe(json.dumps({"model": "fixture-model", "usage": {"input_tokens": 10, "output_tokens": 3,
                      "input_tokens_details": {"cached_tokens": 4}}}), record)
        self.assertEqual(record["usage"]["cached_input_tokens"], 4)
        relay.records.append(record)
        self.assertEqual(relay.usage()["cached_input_tokens"], 4)
        partial = {}
        with self.assertRaisesRegex(ValueError, "different model"):
            relay.observe(json.dumps({"model": "wrong-model", "usage": {"input_tokens": 7}}), partial)
        self.assertEqual(partial["observed_partial_usage"], {"input_tokens": 7})
        self.assertNotIn("usage", partial)
        wrong = {}
        with self.assertRaises(ValueError):
            relay.observe(json.dumps({"model": "wrong-model", "usage": {"input_tokens": 7, "output_tokens": 1}}), wrong)
        self.assertEqual(wrong["usage"], {"input_tokens": 7, "output_tokens": 1})

    def test_appserver_two_turn_contract_keeps_native_and_wire_snapshots_separate(self):
        relay = self.relay()
        server = FactoryAppServer.__new__(FactoryAppServer)
        server.usage, server.events, server.runtime_identity = None, [], {}
        server._proxy_relay, server._policy_cwd = relay, str(self.root)
        server._reuse_session, server.token_limit = True, 1000
        server.MODEL, server.REASONING_EFFORT = "fixture-model", None
        turn = [0]
        def request(method, params):
            self.assertEqual(method, "turn/start")
            turn[0] += 1
            return {"turn": {"id": str(turn[0])}}
        def completed(thread_id, turn_id, require_success):
            self.post(relay)
            event = {"method": "thread/tokenUsage/updated", "params": {
                "threadId": thread_id, "turnId": turn_id, "tokenUsage": {"total": {
                    "inputTokens": 100*turn[0], "outputTokens": 10*turn[0], "totalTokens": 110*turn[0]}}}}
            server.events.append(event)
            server._observe_execution_event(event)
            return {"status": "completed", "items": [{"id": "result", "type": "agentMessage",
                    "text": '{"summary":"fixture","known_risks":[]}'}]}
        with patch.object(server, "start_or_resume", return_value="fixture-thread"), patch.object(server, "_request", side_effect=request), patch.object(server, "_policy_params", return_value={}), patch.object(server, "_turn_completed", side_effect=completed):
            first = server.execute("offline contract", {}, return_thread=True)
            self.assertEqual(first["usage"]["total_tokens"], 13)
            original = relay.evidence.read_bytes()
            relay.start_turn(self.root/"second-turn.raw", 5, 13)
            second = server.execute("offline repair", {}, thread_id="fixture-thread", return_thread=True)
            self.assertEqual(second["usage"]["total_tokens"], 26)
            self.assertEqual(second["thread_id"], first["thread_id"])
            self.assertEqual(server._turn_usage_baseline["total"]["totalTokens"], 110)
            self.assertEqual((self.root/"run.proxy.jsonl").read_bytes(), original)

    def test_unknown_factory_operation_keeps_reservation_and_immutable_evidence(self):
        source = self.root/"source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=t@localhost", "commit", "--allow-empty", "-qm", "baseline"], check=True)
        config = fixture_config()
        config["budget"] = {"max_agent_runs": 6, "max_run_tokens": 100, "max_total_tokens": 600}
        factory = Factory(self.root/"state", config, AcceptanceRuntime())
        self.addCleanup(factory.close)
        mission = factory.submit({"version": 2, "mission_id": "unknown", "repository": str(source), "objective": "accounting contract"})
        calls = []
        def fail(transcript):
            calls.append(True)
            raise RuntimeFailure("uncertain proxy", {"input_tokens": 10, "output_tokens": 3}, {"route_type": "cli_proxy"})
        with self.assertRaises(FactoryBlocked):
            factory.operation(mission, "one", "implement", "developer", {}, {}, True, fail)
        row = factory.db.execute("SELECT * FROM operations").fetchone()
        raw = Path(row["evidence"]).read_bytes()
        with self.assertRaises(FactoryBlocked):
            factory.operation(mission, "one", "implement", "developer", {}, {}, True, fail)
        self.assertEqual(calls, [True])
        self.assertEqual(Path(row["evidence"]).read_bytes(), raw)
        from harness.factory_budget import accounting
        use = accounting(factory.db.execute("SELECT * FROM operations").fetchall(), config["budget"])
        self.assertEqual(use["agent_runs"], 1)
        self.assertEqual(use["observed_tokens"], 13)
        self.assertEqual(use["unknown_token_reservation"], 100)

    @unittest.skipUnless(shutil.which("codex") and shutil.which("bwrap"), "native offline Codex required")
    def test_native_proxy_has_private_home_no_real_key_in_argv_or_delegated_environment(self):
        candidate_tmp = tempfile.TemporaryDirectory(prefix="cmh-proxy-native-candidate-")
        self.addCleanup(candidate_tmp.cleanup)
        cwd = Path(candidate_tmp.name)
        subprocess.run(["git", "init", "-q", str(cwd)], check=True)
        home_tmp = tempfile.TemporaryDirectory(prefix="cmh-proxy-original-home-")
        self.addCleanup(home_tmp.cleanup)
        home = Path(home_tmp.name)
        self.write(home/"auth.json", '{"tokens":"fake-private-auth"}')
        server = FactoryAppServer({**self.profile, "codex_home": str(home)}, cwd, self.root/"native.raw", 30, [home], True)
        nonce = server._proxy_relay.nonce
        private_home = Path(server._proxy_home.name)
        try:
            config = server._request("config/read", {"includeLayers": False})["config"]
            selected = config["model_providers"][server._transport_provider]
            self.assertFalse(selected["requires_openai_auth"])
            self.assertEqual(selected["request_max_retries"], 0)
            self.assertNotIn(self.key, json.dumps(config))
            self.assertNotIn(self.key, Path(f"/proc/{server.proc.pid}/cmdline").read_text())
            self.assertNotIn(nonce, Path(f"/proc/{server.proc.pid}/cmdline").read_text())
            server.start_or_resume(None, str(cwd))
            response = server._request("command/exec", {"command": ["/usr/bin/python3", "-c", "import os,json;print(json.dumps(dict(os.environ)))"], "cwd": str(cwd), "permissions": server._permissions_profile, "timeoutMs": 10000})
            env = json.loads(response["stdout"])
            self.assertNotIn("CODEX_HOME", env)
            self.assertNotIn(self.key, response["stdout"])
            self.assertNotIn(nonce, response["stdout"])
            self.assertFalse(any(e.get("method")=="turn/started" for e in server.events))
        finally:
            server.close()
        self.assertFalse(private_home.exists())
        self.assertNotIn(nonce, (self.root/"native.raw").read_text())

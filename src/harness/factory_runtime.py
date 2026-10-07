"""Thin, bounded execution adapters. Codex owns coding and review intelligence."""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import time
import tomllib
import uuid
import sys
import urllib.request
import urllib.parse
import tempfile
from pathlib import Path

from .codex import AppServerCodex
from .model_registry import read_private_token
from .sandbox import project_gate_invocation, preflight_project_gate, SAFE_PATH
from .factory_proxy import validate_transport, ProxyPolicy, ProxyRelay, digest as route_digest


VENDOR = Path(__file__).parent / "vendor" / "codex"


def official_rubric() -> str:
    manifest = json.loads((VENDOR / "provenance.json").read_text())
    data = (VENDOR / "review-rubric.md").read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest["files"]["review-rubric.md"]["sha256"]:
        raise RuntimeError("official review rubric integrity failure")
    return data.decode()


def validate_openai_route(config):
    """A provider label cannot turn a DeepSeek/custom endpoint into OpenAI."""
    urls = [config.get("model_providers", {}).get("openai", {}).get("base_url"), config.get("chatgpt_base_url")]
    for value in filter(lambda x: x is not None, urls):
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname not in ("api.openai.com", "chatgpt.com") or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("OpenAI route is not an official endpoint; independent provider identity is unproven")


def official_route_identity(profile, home):
    return {"route_type": "official", "configured_provider": "openai", "auth_source": str(Path(home)/"auth.json"),
            "codex_home": str(home), "requested_model": profile.get("model"),
            "endpoint_selection": "native_official_auth"}


def obj(properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties),
            "additionalProperties": False}


TEXT = {"type": "string"}
SCORE = {"type": "number", "minimum": 0, "maximum": 1}
REVIEW_SCHEMA = obj({
    "findings": {"type": "array", "items": obj({
        "title": TEXT, "body": TEXT, "confidence_score": SCORE,
        "priority": {"type": ["integer", "null"], "minimum": 0, "maximum": 3},
        "code_location": obj({"absolute_file_path": TEXT,
                              "line_range": obj({"start": {"type": "integer", "minimum": 1},
                                                 "end": {"type": "integer", "minimum": 1}})}),
    })},
    "overall_correctness": {"type": "string", "enum": ["patch is correct", "patch is incorrect"]},
    "overall_explanation": TEXT, "overall_confidence_score": SCORE,
})
PLAN_SCHEMA = obj({"plan": TEXT, "tasks": {"type": "array", "items": TEXT},
                   "acceptance": {"type": "array", "items": TEXT},
                   "decisions_required": {"type": "array", "items": TEXT}})
WORK_SCHEMA = obj({"summary": TEXT, "known_risks": {"type": "array", "items": TEXT}})


class FactoryAppServer(AppServerCodex):
    """Reuse the existing protocol/security adapter without its legacy global qualification.

    Profiles are lane-local. Each run gets a fresh thread, a transcript, and a
    constructor-bound permission profile. No previous review is in its history.
    """

    def __init__(self, profile: dict, cwd: Path, transcript: Path, timeout: int,
                 denied_roots: list[Path], read_only: bool, reviewer: bool = False, token_limit: int | None = None):
        self._policy_cwd = self._canonical_worktree(str(cwd))
        self._forbidden_actions = self._effective_policy(("release",))
        self._configured_forbidden_actions = self._forbidden_actions
        self._permissions_profile = f"cmh_delegated_{uuid.uuid4().hex}"
        self.MODEL = profile.get("model")
        self.REASONING_EFFORT = profile.get("effort")
        self.token_limit = token_limit
        self.profile, self.read_only = profile, read_only
        self.reviewer = reviewer
        self.runtime_identity = None
        self.transport = validate_transport(profile, reviewer)
        self._proxy_relay = None
        self._proxy_home = None
        # Built-in OpenAI ignores configured retry overrides. A fresh official
        # provider entry uses native authentication/endpoint selection while
        # disabling ambiguous request replay and transport fallback.
        self._transport_provider = "cmh_openai_" + uuid.uuid4().hex
        self.events: list[dict] = []
        self.usage = None
        self.transcript, self._transcript_bytes = transcript, 0
        self._response_timeout = timeout
        self._end_time = time.monotonic() + timeout
        home = None
        self._source_home = str(Path(profile.get("codex_home") or Path.home()/".codex"))
        if self.transport["type"] == "cli_proxy":
            secrets_root = Path(self.transport["policy_file"]).parent
            if secrets_root.is_relative_to(cwd) or cwd.is_relative_to(secrets_root):
                raise ValueError("proxy authentication directory must remain outside the candidate")
            # Neither the user's OAuth nor a bearer token is handed to Codex.
            # A private run-local home contains only an observer capability;
            # the actual proxy credential stays in the controller process.
            self._proxy_home = tempfile.TemporaryDirectory(prefix="cmh-proxy-home-")
            home = self._proxy_home.name
            self._transport_provider = "cmh_cli_proxy_" + uuid.uuid4().hex
        else:
            home = self._codex_home(profile.get("codex_home"))
            self._source_home = home
        executable = self._trusted_executable("codex", str(cwd))
        self._native_identity = {"executable": str(executable), "launcher_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
        watchdog = self._trusted_executable("timeout", str(cwd))
        rules = {str(root): "deny" for root in denied_roots if not (read_only and root in cwd.parents)}
        if not read_only:
            rules[":root"] = "deny"
        rules[":minimal"] = "read"
        rules[str(cwd)] = "read" if read_only else "write"
        # npm's trusted launcher executes its bundled Rust sandbox helper.
        # A minimal read profile must expose that installed package as well.
        installed_runtime = executable.parent.parent if executable.name == "codex.js" and (executable.parent.parent / "package.json").is_file() else executable.parent
        rules[str(installed_runtime)] = "read"
        rules[home] = "deny"
        if self.transport["type"] == "cli_proxy":
            rules[self._source_home] = "deny"
            rules[str(Path(self.transport["policy_file"]).parent)] = "deny"
        # The Git database belongs to the controller, not to coding agents.
        rules[str(cwd / ".git")] = "read"
        # A read-only lane starts with minimal runtime + the exact repository,
        # rather than inheriting the built-in profile's broad host read grant.
        overrides = ([] if read_only else ["-c", f'permissions.{self._permissions_profile}.extends=":workspace"']) + [
                     "-c", f"default_permissions={json.dumps(self._permissions_profile)}",
                     "-c", f"permissions.{self._permissions_profile}.filesystem=" +
                     "{" + ",".join(f"{json.dumps(k)}={json.dumps(v)}" for k, v in rules.items()) + "}",
                     "-c", f"permissions.{self._permissions_profile}.network.enabled=false",
                     "-c", "model_provider=" + json.dumps(self._transport_provider),
                     "-c", "model_providers." + self._transport_provider + '={name="OpenAI",wire_api="responses",requires_openai_auth=true,request_max_retries=0,stream_max_retries=0,supports_websockets=false}',
                     "-c", "features.unbounded_connection_retries=false",
                     "-c", "features.responses_websockets=false",
                     "-c", "features.responses_websockets_v2=false",
                     "-c", "web_search=\"disabled\"",
                     "-c", "features.multi_agent=false",
                     "-c", "features.multi_agent_v2=false",
                     "-c", "features.apps=false",
                     "-c", "features.hooks=false",
                     # cwd is constructor-verified as the Git repository root;
                     # parent traversal would probe private factory directories.
                     "-c", "project_root_markers=[]",
                     "-c", "mcp_servers={}",
                     "-c", "plugins={}",
                     "-c", 'shell_environment_policy.filters.CODEX_HOME="exclude"',
                     "-c", 'shell_environment_policy.set.PYTHONDONTWRITEBYTECODE="1"']
        if token_limit:
            # Native Codex budget stops its own sampling loop. Controller also
            # checks unweighted telemetry, including cached input tokens.
            overrides.extend(["-c", "features.rollout_budget=" + json.dumps(
                {"enabled": True, "limit_tokens": token_limit, "reminder_at_remaining_tokens": ([max(1, token_limit // 4)] if token_limit > 1 else []),
                 "sampling_token_weight": 1.0, "prefill_token_weight": 1.0}).replace(': ', '=')])
        if profile.get("codex_profile"):
            overrides = ["--profile", profile["codex_profile"], *overrides]
        if self.MODEL:
            overrides.extend(["-c", "model=" + json.dumps(self.MODEL)])
        if self.REASONING_EFFORT:
            overrides.extend(["-c", "model_reasoning_effort=" + json.dumps(self.REASONING_EFFORT)])
        # TOML layers merge tables, so an empty table does NOT disable inherited
        # MCP servers. Disable each configured server explicitly at highest priority.
        config_files = [Path(home) / "config.toml"]
        if profile.get("codex_profile"):
            config_files.append(Path(home) / (profile["codex_profile"] + ".config.toml"))
        config_files.extend(parent / ".codex/config.toml" for parent in (cwd, *cwd.parents))
        self.disabled_mcp = {}
        disabled_plugins = set()
        for config_file in config_files:
            if config_file.is_file():
                source_config = tomllib.loads(config_file.read_text())
                validate_openai_route(source_config)
                for name, server_config in source_config.get("mcp_servers", {}).items():
                    # Codex filters untrusted project transports before CLI
                    # overrides. An enabled=false-only override then has no
                    # transport and fails deserialization even while disabled.
                    # Keep an inert, valid transport of the same kind; never
                    # copy credentials, args or environment into our override.
                    if "command" in server_config:
                        transport = {"command": "/bin/false"}
                    elif "url" in server_config:
                        transport = {"url": "http://127.0.0.1:1/disabled-mcp"}
                    else:
                        raise ValueError("configured MCP server has no valid transport")
                    self.disabled_mcp[name] = {"enabled": False, **transport}
                for name in source_config.get("plugins", {}):
                    disabled_plugins.add(name)
        disabled_entries = []
        for name, settings in self.disabled_mcp.items():
            transport_key = "command" if "command" in settings else "url"
            disabled_entries.append(json.dumps(name) + "={enabled=false," + transport_key + "=" + json.dumps(settings[transport_key]) + "}")
        overrides.extend(["-c", "mcp_servers={" + ",".join(disabled_entries) + "}"])
        overrides.extend(["-c", "plugins={" + ",".join(json.dumps(name) + "={enabled=false}" for name in disabled_plugins) + "}"])
        if self.transport["type"] == "cli_proxy":
            try:
                self._proxy_relay = ProxyRelay(profile, transcript, timeout, token_limit)
                # This exact table has no inherited fields and no real API key.
                provider = {"name": "Explicit CLI Proxy", "base_url": self._proxy_relay.base_url,
                            "wire_api": "responses", "requires_openai_auth": False,
                            "experimental_bearer_token": self._proxy_relay.nonce,
                            "request_max_retries": 0, "stream_max_retries": 0,
                            "supports_websockets": False}
                # TOML is generated without putting credentials in command args.
                (Path(home) / "config.toml").write_text("[model_providers." + self._transport_provider + "]\n" +
                    "\n".join(k + "=" + json.dumps(v) for k,v in provider.items()) + "\n")
                (Path(home) / "config.toml").chmod(0o600)
                index = next(i for i,x in enumerate(overrides) if x.startswith("model_providers." + self._transport_provider + "="))
                # Avoid merging the official-auth table into the proxy table.
                del overrides[index-1:index+1]
            except BaseException:
                self.close()
                raise
        try:
            with transcript.with_suffix(".stderr").open("xb") as stderr:
                # GNU coreutils supplies a wall-clock watchdog independent of
                # this controller; unknown dispatch stays charged/unreplayed.
                environment = self._app_server_environment(str(executable), str(cwd), codex_home=home)
                if self.transport["type"] == "cli_proxy":
                    # Codex talks only to the local observer. Upstream network
                    # routing belongs to the explicit dedicated proxy config.
                    environment = {k:v for k,v in environment.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
                    environment["NO_PROXY"] = "127.0.0.1,localhost,::1"
                self.proc = subprocess.Popen([str(watchdog), "--signal=TERM", "--kill-after=5", str(timeout),
                                             str(executable), *overrides, "app-server", "--stdio"],
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=stderr, text=True, bufsize=1, cwd=cwd, start_new_session=True,
                                             env=environment)
        except BaseException:
            self.close()
            raise
        self.seq = 0
        self._pending_messages = []
        self._reader_thread = None
        try:
            initialized = self._request("initialize", {"clientInfo": {"name": "software-delivery-factory", "version": "1"},
                                                        "capabilities": {"experimentalApi": True}})
            self._native_identity["reported_server"] = initialized.get("userAgent")
            self.proc.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
            self.proc.stdin.flush()
        except BaseException:
            self.close()
            raise

    def _deadline(self) -> float:
        return self._end_time

    def _observe_wire_line(self, line):
        if getattr(self, "_proxy_relay", None):
            # config/read and native diagnostics can echo the capability.
            line = line.replace(self._proxy_relay.nonce, "[REDACTED]")
        data = line.encode()
        self._transcript_bytes += len(data)
        if self._transcript_bytes > 16 * 1024 * 1024:
            self.close()
            raise RuntimeError("App Server transcript limit exceeded")
        with self.transcript.open("ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def _read_message(self, deadline=None):
        message = super()._read_message(deadline)
        self.events.append(message)
        if message.get("method") == "thread/tokenUsage/updated":
            self.usage = message.get("params", {}).get("tokenUsage")
            from .factory_budget import tokens
            if self.token_limit and (tokens(self.usage) or 0) > self.token_limit:
                raise RuntimeFailure("Codex token telemetry exceeded run allowance", self.usage, self.runtime_identity)
        return message

    def _request(self, method, params):
        result = super()._request(method, params)
        if method == "thread/start":
            self.runtime_identity = {"model": result.get("model"), "provider": "openai", "transport_provider": result.get("modelProvider"),
                                     "transport": {"route_type": self.transport["type"], "official_auth": self.transport["type"] == "official", "request_max_retries": 0, "stream_max_retries": 0, "supports_websockets": False},
                                     "effort": result.get("reasoningEffort"), "profile": self.profile}
            self.runtime_identity["native_runtime"] = self._native_identity
            if self._proxy_relay:
                route = {**self.transport, "route_type": "cli_proxy", "requested_model": self.MODEL, "auth_source": self._proxy_relay.policy.policy["credential_file"],
                         "runtime": self._proxy_relay.policy.identity}
                self.runtime_identity.update(route_identity=route, qualification_identity=route_digest(route),
                                             upstream_provider_identity="NOT_PROVABLE", reported_model=None)
            else:
                route = official_route_identity(self.profile, self._source_home)
                self.runtime_identity.update(route_identity=route, qualification_identity=route_digest({"route": route, "profile": self.profile, "runtime": self._native_identity}),
                                             requested_model=self.MODEL, reported_model=result.get("model"),
                                             model_identity_source="official_app_server_thread_model_and_reroute_events")
            if result.get("modelProvider") != self._transport_provider or not result.get("model"):
                raise RuntimeError("Codex runtime provider/model identity is unproven")
            if self.MODEL and result["model"] != self.MODEL:
                raise RuntimeError("Codex runtime selected a different configured model")
        return result

    def _thread_policy_params(self, cwd):
        params = super()._thread_policy_params(cwd)
        if self.MODEL is None:
            params.pop("model")
        params["modelProvider"] = self._transport_provider
        params["ephemeral"] = True
        if self.reviewer:
            params["baseInstructions"] = official_rubric()
        # Disable remote tools; their independent authority is outside this local factory.
        params["config"]["mcp_servers"] = self.disabled_mcp
        params["config"]["features"] = {"hooks": False, "apps": False, "multi_agent": False, "multi_agent_v2": False}
        params["config"]["project_root_markers"] = []
        return params

    def execute(self, prompt: str, schema: dict) -> dict:
        thread_id = self.start_or_resume(None, self._policy_cwd)
        params = {"threadId": thread_id, "input": [{"type": "text", "text": prompt}],
                  "outputSchema": schema, **self._policy_params(self._policy_cwd)}
        if self.MODEL:
            params["model"] = self.MODEL
        if self.REASONING_EFFORT:
            params["effort"] = self.REASONING_EFFORT
        accepted = self._request("turn/start", params)
        turn_id = accepted["turn"]["id"]
        completed = self._turn_completed(thread_id, turn_id)
        routed = [e["params"] for e in self.events if e.get("method") == "model/rerouted" and e.get("params", {}).get("threadId") == thread_id]
        if self.MODEL and any(e.get("toModel") != self.MODEL for e in routed):
            raise RuntimeError("explicit configured model was rerouted; exact model identity changed")
        self.runtime_identity.update(thread_id=thread_id, turn_id=turn_id, model_routing=routed)
        items = {i["id"]: i for i in completed.get("items", []) if "id" in i}
        for event in self.events:
            p = event.get("params", {})
            if p.get("threadId") == thread_id and p.get("turnId") == turn_id:
                if event.get("method") == "item/completed":
                    item = p.get("item", {})
                    if "id" in item:
                        items[item["id"]] = item
                if event.get("method") == "thread/tokenUsage/updated":
                    self.usage = p.get("tokenUsage")
        text = [i["text"] for i in items.values() if i.get("type") == "agentMessage"
                and i.get("phase") in (None, "final_answer")]
        if not text:
            raise RuntimeError("completed Codex turn has no structured final result")
        receipt = None
        if getattr(self, "_proxy_relay", None):
            self._proxy_relay.collect_telemetry()
            receipt = self._proxy_relay.receipt()
            self.usage = self._proxy_relay.usage()
            self.runtime_identity["physical_accounting"] = receipt
            self.runtime_identity["reported_model"] = self.MODEL if receipt["usage_complete"] else None
            if not receipt["usage_complete"]:
                raise RuntimeFailure("explicit proxy result/usage identity is uncertain; no replay", self.usage, self.runtime_identity)
        return {"output": json.loads(text[-1]), "usage": self.usage,
                "thread_id": thread_id, "turn_id": turn_id,
                "runtime_identity": self.runtime_identity, "model_routing": routed,
                **({"physical_accounting": receipt, "usage_complete": receipt["usage_complete"]} if receipt else {})}

    def close(self):
        proc = getattr(self, "proc", None)
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        super().close()
        relay = getattr(self, "_proxy_relay", None)
        if relay:
            relay.close()
            error = self.transcript.with_suffix(".stderr")
            if error.exists():
                error.write_bytes(error.read_bytes().replace(relay.nonce.encode(), b"[REDACTED]"))
            self._proxy_relay = None
        home = getattr(self, "_proxy_home", None)
        if home:
            home.cleanup()
            self._proxy_home = None


class LocalRuntime:
    """Codex turns + existing bubblewrap gates + a separate DeepSeek API lane."""

    simulation = False

    def __init__(self):
        self.resource_policy = {}
        self.current_process = None

    def cancel(self):
        proc = self.current_process
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def profile_identity(self, profile):
        identity = {"configured": profile}
        if profile["provider"] == "openai":
            transport = validate_transport(profile)
            if transport["type"] == "cli_proxy":
                policy = ProxyPolicy(transport)
                route = {**transport, "route_type": "cli_proxy", "auth_source": policy.policy["credential_file"], "requested_model": profile["model"], "runtime": policy.identity}
                identity["route_identity"] = route
                identity["qualification_identity"] = route_digest(route)
            home = Path(AppServerCodex._codex_home(profile.get("codex_home"))) if transport["type"] == "official" else None
            selected = [home / "config.toml"] if home else []
            if profile.get("codex_profile"):
                selected.append(home / (profile["codex_profile"] + ".config.toml"))
            # Codex writes project trust bookkeeping when opening a new
            # checkout. That is not a model/profile change and must not
            # silently invalidate prior reviews on every subsequent task.
            configs = {}
            for path in selected:
                if path.exists():
                    semantic = tomllib.loads(path.read_text())
                    semantic.pop("projects", None)
                    canonical = json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()
                    configs[path.name] = hashlib.sha256(canonical).hexdigest()
                else:
                    configs[path.name] = None
            identity["codex_config_hashes"] = configs if transport["type"] == "official" else {}
            if transport["type"] == "official":
                identity["route_identity"] = official_route_identity(profile, home)
                identity["qualification_identity"] = route_digest({"route": identity["route_identity"], "profile": profile})
            binary = AppServerCodex._trusted_executable("codex")
            identity["native_runtime"] = {"executable": str(binary), "launcher_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
            identity["runtime_version"] = subprocess.check_output([str(binary), "--version"], timeout=10, text=True).strip()
        else:
            identity["route"] = "https://api.deepseek.com/chat/completions"
            route = {"route_type": "direct", "configured_provider": "deepseek", "endpoint": identity["route"],
                     "auth_source": profile["token_file"], "requested_model": profile["model"]}
            identity["route_identity"] = route
            identity["qualification_identity"] = route_digest(route)
        identity["adapter_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        dependencies = ["codex.py", "factory_proxy.py"] if profile["provider"] == "openai" else ["factory_http.py", "model_registry.py"]
        identity["transport_hashes"] = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in dependencies}
        return identity

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        server = FactoryAppServer(profile, cwd, transcript, timeout, denied_roots,
                                  role in ("plan", "review"), role == "review", self.resource_policy.get("max_run_tokens"))
        self.current_process = server.proc
        try:
            schema = REVIEW_SCHEMA if role == "review" else PLAN_SCHEMA if role == "plan" else WORK_SCHEMA
            return server.execute(json.dumps(payload, ensure_ascii=False), schema)
        except Exception as exc:
            if server._proxy_relay:
                try:
                    server._proxy_relay.collect_telemetry()
                except Exception:
                    pass  # Unknown telemetry cannot settle the reservation.
                server.usage = server._proxy_relay.usage()
                if server.runtime_identity is not None:
                    server.runtime_identity["physical_accounting"] = server._proxy_relay.receipt()
                # Never include upstream error bodies, credentials or transport
                # exception reprs in a receipt for a proxy failure.
                raise RuntimeFailure("explicit CLI proxy run failed; no retry or fallback", server.usage, server.runtime_identity) from exc
            raise RuntimeFailure(str(exc), server.usage, server.runtime_identity) from exc
        finally:
            server.close()
            self.current_process = None

    def second_review(self, profile, cwd, payload, transcript, timeout):
        # A separate bounded process makes cancellation, controller death and
        # total wall-clock independent of socket per-read timeout behavior.
        watchdog = AppServerCodex._trusted_executable("timeout", str(cwd))
        env = {"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8",
               "PYTHONPATH": str(Path(__file__).resolve().parent.parent)}
        for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
                    "https_proxy", "http_proxy", "all_proxy", "no_proxy"):
            if key in os.environ:
                env[key] = os.environ[key]
        proc = subprocess.Popen([str(watchdog), "--signal=TERM", "--kill-after=5", str(timeout),
                                 sys.executable, "-m", "harness.factory_http"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, cwd=cwd, env=env, start_new_session=True)
        self.current_process = proc
        try:
            output, error = proc.communicate(json.dumps({"profile": profile, "payload": payload,
                                                         "transcript": str(transcript), "timeout": timeout}), timeout=timeout + 6)
            if proc.returncode:
                raise RuntimeFailure(f"DeepSeek transport failed ({proc.returncode}): {error[-2000:]}")
            result = json.loads(output)
            if "error" in result:
                raise RuntimeFailure(result["error"], result.get("usage"), result.get("runtime_identity"), usage_complete=result.get("usage_complete", False))
            return result
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            self.current_process = None

    def hosted_ci(self, policy, cwd, target, branch, transcript, timeout):
        watchdog = AppServerCodex._trusted_executable("timeout", str(cwd))
        env = {"PATH": SAFE_PATH, "HOME": str(Path.home()), "LANG": "C.UTF-8",
               "PYTHONPATH": str(Path(__file__).resolve().parent.parent)}
        for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy"):
            if key in os.environ:
                env[key] = os.environ[key]
        proc = subprocess.Popen([str(watchdog), "--signal=TERM", "--kill-after=5", str(timeout),
                                 sys.executable, "-m", "harness.factory_hosted"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd, env=env, start_new_session=True)
        self.current_process = proc
        try:
            output, error = proc.communicate(json.dumps({"policy": policy, "cwd": str(cwd), "target": target,
                                "branch": branch, "transcript": str(transcript), "timeout": timeout}), timeout=timeout + 6)
            if proc.returncode:
                raise RuntimeFailure(f"hosted CI transport failed ({proc.returncode}): {error[-2000:]}")
            return json.loads(output)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            self.current_process = None

    def gate(self, command, cwd, target, transcript, timeout):
        environment = {"BASE_REF": target["base"], "HEAD_REF": target["head"]}
        if target.get("mission_scope_file"):
            environment["MISSION_SCOPE_FILE"] = str(cwd / target["mission_scope_file"])
        invocation = project_gate_invocation(command, str(cwd),
                                             environment,
                                             transcript.parent / "sandbox", uuid.uuid4().hex)
        preflight_project_gate(invocation)
        with transcript.open("xb") as log:
            proc = subprocess.Popen(invocation.argv, cwd=invocation.cwd, env=invocation.env,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            self.current_process = proc
            try:
                code = proc.wait(timeout=timeout)
            except BaseException:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise
            finally:
                self.current_process = None
        return {"status": "PASS" if code == 0 else "FAIL", "exit_code": code,
                "log": transcript.read_text(errors="replace")[-64000:]}


class RuntimeFailure(RuntimeError):
    def __init__(self, message, usage=None, identity=None, *, usage_complete=False):
        self.usage, self.identity = usage, identity
        self.usage_complete = usage_complete
        super().__init__(message)

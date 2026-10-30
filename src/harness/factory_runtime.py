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
from .factory_project import FootballPredictionContract, LANES


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
                 denied_roots: list[Path], read_only: bool, reviewer: bool = False, token_limit: int | None = None,
                 protected_paths: tuple[Path, ...] = ()):
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
        self._usage_thread_id = self._usage_turn_id = None
        self._usage_by_thread = {}
        self._usage_scope_errors = []
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
        self._native_identity = {"executable": str(executable), "launcher_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                                 "execution_limits": {"token_limit": token_limit, "timeout_seconds": timeout,
                                                      "physical_token_ceiling": "NOT_GUARANTEED"}}
        watchdog = self._trusted_executable("timeout", str(cwd))
        rules = {str(root): "deny" for root in denied_roots if not (read_only and root in cwd.parents)}
        if not read_only:
            rules[":root"] = "deny"
        rules[":minimal"] = "read"
        rules[str(cwd)] = "read" if read_only else "write"
        for path in protected_paths:
            if path.is_symlink() or not path.is_relative_to(cwd):
                raise ValueError("protected Controller scope must be inside the candidate")
            rules[str(path)] = "read"
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
                     # Codex 0.164 keeps the legacy feature keys, but native
                     # collaboration is controlled by agents.enabled.
                     "-c", "agents.enabled=false",
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
        self._observe_execution_event(message)
        return message

    def _bind_usage_thread(self, thread_id):
        if getattr(self, "_usage_thread_id", None) is not None:
            raise RuntimeError("native execution must use one fresh thread")
        self._usage_thread_id, self._usage_turn_id = thread_id, None
        self._usage_by_thread, self._usage_scope_errors = {}, []
        self._early_activity = []
        self._early_activity_bytes = 0
        self.usage = None

    def usage_telemetry(self):
        # Each value is a thread-cumulative snapshot associated with a turn,
        # NOT a turn delta or a separately billable quantity. Never sum them.
        return {"thread_id": getattr(self, "_usage_thread_id", None),
                "turn_id": getattr(self, "_usage_turn_id", None),
                "by_thread": getattr(self, "_usage_by_thread", {}),
                "scope_errors": getattr(self, "_usage_scope_errors", []),
                "early_activity": getattr(self, "_early_activity", []),
                "scope": "one fresh thread and one authorized turn",
                "provider_total_usage": "UNKNOWN", "cross_thread_aggregation": "NOT_PERFORMED"}

    def _usage_failure(self, reason, attribution=None):
        if attribution is not None:
            self._usage_scope_errors.append(attribution)
        raise RuntimeFailure(reason, self.usage, self.runtime_identity,
                             usage_telemetry=self.usage_telemetry())

    def _accept_root_usage(self, usage):
        from .factory_budget import tokens
        count = tokens(usage)
        if count is None:
            self._usage_failure("native usage is not a valid attributed token count")
        self.usage = usage
        if self.token_limit and count > self.token_limit:
            self._usage_failure("Codex token telemetry exceeded run allowance")

    def _bind_usage_turn(self, turn_id):
        if not isinstance(turn_id, str) or not turn_id:
            self._usage_failure("native turn identity is missing")
        if self._usage_turn_id not in (None, turn_id):
            self._usage_failure("native turn/start response changed the observed turn identity")
        self._usage_turn_id = turn_id
        if isinstance(self.runtime_identity, dict):
            self.runtime_identity.update(thread_id=self._usage_thread_id, turn_id=turn_id)
        for event in self._early_activity:
            params = event["params"]
            observed = params.get("turn", {}).get("id") if isinstance(params.get("turn"), dict) else params.get("turnId")
            if params.get("threadId") != self._usage_thread_id or observed != turn_id:
                self._usage_failure("early activity belongs to an unauthorized native thread/turn", event)
        # Notifications can precede the turn/start response. Attribute them
        # only after matching the returned turn, never to whichever arrived last.
        for observed_turn, record in self._usage_by_thread.get(self._usage_thread_id, {}).items():
            if observed_turn != turn_id:
                self._usage_failure("usage belongs to another native turn",
                                    {"threadId": self._usage_thread_id, "turnId": observed_turn})
            self._accept_root_usage(record["last_token_usage"])

    def _observe_execution_event(self, message):
        method, params = message.get("method"), message.get("params", {})
        # Native 0.164 execution notifications in these namespaces carry both
        # identities, including deltas and errors received before acceptance.
        activity = isinstance(method, str) and (method.startswith(("turn/", "item/", "model/")) or method == "error")
        if not isinstance(params, dict):
            if activity:
                self._usage_failure("native activity has malformed attribution", message)
            return
        item = params.get("item", {})
        if isinstance(item, dict) and item.get("type") in ("subAgentActivity", "collabAgentToolCall"):
            self._usage_failure("native delegation observed although disabled",
                                {"method": method, "threadId": params.get("threadId"),
                                 "item_type": item["type"], "agentThreadId": item.get("agentThreadId")})
        if self._usage_thread_id and activity:
            observed_thread = params.get("threadId")
            observed_turn = params.get("turn", {}).get("id") if isinstance(params.get("turn"), dict) else params.get("turnId")
            if ("turn" in params and (not isinstance(params["turn"], dict)
                    or ("turnId" in params and params["turnId"] != observed_turn))):
                self._usage_failure("native activity has conflicting turn attribution", message)
            if self._usage_turn_id is None:
                size = len(json.dumps(message).encode())
                if len(self._early_activity) >= 256 or self._early_activity_bytes + size > 262144:
                    self._usage_failure("early native activity buffer exceeded", message)
                self._early_activity.append(message)
                self._early_activity_bytes += size
            if not all(isinstance(v, str) and v for v in (observed_thread, observed_turn)):
                self._usage_failure("native activity has no thread/turn attribution", message)
            if observed_thread != self._usage_thread_id or (self._usage_turn_id and observed_turn != self._usage_turn_id):
                self._usage_failure("activity belongs to an unauthorized native thread/turn",
                                    message)
            if method == "turn/started":
                self._bind_usage_turn(observed_turn)
        if method != "thread/tokenUsage/updated":
            return
        thread_id, turn_id = params.get("threadId"), params.get("turnId")
        if not all(isinstance(v, str) and v for v in (thread_id, turn_id)):
            self._usage_failure("usage notification has no thread/turn attribution",
                                {"method": method, "threadId": thread_id, "turnId": turn_id,
                                 "tokenUsage": params.get("tokenUsage")})
        record = self._usage_by_thread.setdefault(thread_id, {}).setdefault(turn_id, {"notifications": 0})
        record.update(notifications=record["notifications"] + 1, last_token_usage=params.get("tokenUsage"))
        if thread_id != self._usage_thread_id:
            self._usage_failure("usage belongs to an unauthorized native thread",
                                {"threadId": thread_id, "turnId": turn_id})
        if self._usage_turn_id is not None:
            if turn_id != self._usage_turn_id:
                self._usage_failure("usage belongs to another native turn",
                                    {"threadId": thread_id, "turnId": turn_id})
            self._accept_root_usage(params.get("tokenUsage"))

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
        params["config"]["agents"] = {"enabled": False}
        params["config"]["project_root_markers"] = []
        return params

    def execute(self, prompt: str, schema: dict) -> dict:
        thread_id = self.start_or_resume(None, self._policy_cwd)
        self._bind_usage_thread(thread_id)
        params = {"threadId": thread_id, "input": [{"type": "text", "text": prompt}],
                  "outputSchema": schema, **self._policy_params(self._policy_cwd)}
        if self.MODEL:
            params["model"] = self.MODEL
        if self.REASONING_EFFORT:
            params["effort"] = self.REASONING_EFFORT
        accepted = self._request("turn/start", params)
        turn_id = accepted["turn"]["id"]
        self._bind_usage_turn(turn_id)
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
                "usage_telemetry": self.usage_telemetry(),
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
        import threading
        self.resource_policy = {}
        self.current_process = None
        self.container_cancel = threading.Event()
        self._execution_lock = threading.RLock()
        self._active_execution = self._active_mission = None
        self._execution_thread = None

    def begin_execution(self, mission):
        import threading
        with self._execution_lock:
            if self._active_execution is not None or self.current_process is not None:
                raise RuntimeError("runtime already belongs to an active execution")
            # A new identity, not clearing an old task's cancellation latch.
            self.container_cancel = threading.Event()
            self._active_execution, self._active_mission = self.container_cancel, mission
            self._execution_thread = threading.get_ident()
            return self._active_execution

    def end_execution(self, execution):
        with self._execution_lock:
            if execution is self._active_execution:
                self._active_execution = self._active_mission = None
                self._execution_thread = None

    def cancel(self, execution=None):
        with self._execution_lock:
            if execution is None:
                if self._active_execution is not None:
                    return False  # Factory watchers must supply their execution identity.
            elif execution is not self._active_execution:
                return False  # A delayed callback cannot affect a later mission/run.
            self.container_cancel.set()
            proc = self.current_process
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            return True

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
        token_limit = self.resource_policy.get("max_run_tokens")
        if role == "plan":
            from .factory_budget import planning_limits
            limits = planning_limits(self.resource_policy, timeout)
            token_limit, timeout = limits["max_tokens"], limits["timeout_seconds"]
            payload = {**payload, "planning_resource_guard": {
                **limits, "physical_token_ceiling": "NOT_GUARANTEED",
                "instruction": "Use targeted searches and small excerpts. Do not dump the repository, generated bundles or unrelated documentation. Stop exploring once you can return a bounded actionable plan; if essential information is missing, state the unresolved decision. Do not repeat broad scans."}}
        protected = (cwd / payload["mission_scope_file"],) if payload.get("mission_scope_file") else ()
        server = FactoryAppServer(profile, cwd, transcript, timeout, denied_roots,
                                  role in ("plan", "review"), role == "review", token_limit,
                                  protected_paths=protected)
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
                raise RuntimeFailure("explicit CLI proxy run failed; no retry or fallback", server.usage, server.runtime_identity,
                                     usage_telemetry=server.usage_telemetry()) from exc
            raise RuntimeFailure(str(exc), server.usage, server.runtime_identity,
                                 usage_telemetry=server.usage_telemetry()) from exc
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

    def project_policy(self, spec, cwd, paths):
        return FootballPredictionContract().policy(spec, cwd, paths)

    def project_review_admission(self, spec, cwd, target, limits):
        return FootballPredictionContract().review_admission(spec, cwd, target, limits)

    def container_gate(self, policy, spec, cwd, target, command, transcript, timeout):
        import threading
        from .factory_container import run
        # Direct Controller gates also receive a new task identity. Factory.run
        # already owns an identity for its full execution, including agents.
        with self._execution_lock:
            standalone = self._active_execution is None
            if standalone:
                execution = self.begin_execution(spec["mission_id"])
            elif self._active_mission != spec["mission_id"] or self._execution_thread != threading.get_ident():
                raise RuntimeError("container gate belongs to a different active execution")
        try:
            return run(self, policy, spec, cwd, target, command, transcript, timeout)
        finally:
            if standalone:
                self.end_execution(execution)

    def recover_container(self, policy, spec, target, command, transcript):
        from .factory_container import recover
        return recover(policy, spec, target, command, transcript)

    def prepare_project_review(self, spec, cwd, target, lane, timeout):
        contract = FootballPredictionContract()
        argv, evidence = contract.review_arguments(spec, cwd, target, lane)
        if lane == "reviewer":
            argv += ["--timeout-seconds", str(timeout)]
        watchdog = AppServerCodex._trusted_executable("timeout", str(cwd))
        argv = [str(watchdog), "--signal=TERM", "--kill-after=5", str(timeout), *argv]
        environment = contract.adapter.review_environment(LANES[lane], worktree=str(cwd), base=target["base"])
        return argv, evidence, environment

    def project_review(self, spec, cwd, target, lane, transcript, timeout, *, prepared=None):
        contract = FootballPredictionContract()
        if isinstance(prepared, dict):
            admission = contract.review_admission(spec, cwd, target, prepared["admission"]["authorization"])
            if admission != prepared["admission"]:
                raise ValueError("canonical diff/chunk admission changed before dispatch")
            prepared = prepared["runner"]
        argv, evidence, environment = prepared if prepared is not None else self.prepare_project_review(
            spec, cwd, target, lane, timeout)
        # Recheck the private directory immediately before launch as well.
        contract.adapter._validate_review_evidence_dir(evidence)
        stderr = transcript.with_suffix(".stderr")
        with transcript.open("xb") as output, stderr.open("xb") as errors:
            os.fchmod(output.fileno(), 0o600)
            os.fchmod(errors.fileno(), 0o600)
            proc = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=output,
                                    stderr=errors, start_new_session=True)
            self.current_process = proc
            try:
                code = proc.wait(timeout=timeout + 6)
            except BaseException:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise
            finally:
                self.current_process = None
        result = {"stdout_path": str(transcript), "stderr_path": str(stderr),
                  "evidence_dir": str(evidence), "exit_code": code, "fixture": False,
                  "executed_runner_argv": argv, "usage": None, "usage_complete": False}
        checked = contract.validate_review(spec, cwd, target, lane, result)
        # Reference actual artifacts, not reconstructed CLI provenance. The
        # project's validator verifies the underlying receipt/raw evidence.
        result["project_evidence"] = [{"path": str(path.resolve()),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in evidence.iterdir() if path.is_file() and not path.is_symlink()]
        result["canonical_receipt"] = checked.artifact
        return result

    def project_validate_review(self, spec, cwd, target, lane, result):
        return FootballPredictionContract().validate_review(spec, cwd, target, lane, result)

    def project_final_gate(self, spec, cwd, target, reviews, transcript, timeout, context=None):
        if context is not None:
            return self.project_remote("verify", context["policy"], spec, cwd, target,
                                       context["body"], transcript, timeout, reviews=reviews)
        gate = FootballPredictionContract().final_gate()
        result = {"status": gate.status, "reason": gate.evidence, "target": target, "fixture": False}
        transcript.write_text(json.dumps(result))
        return result

    def project_remote(self, action, policy, spec, cwd, target, body, transcript, timeout, *, reviews=None, previous_head=None):
        import threading
        with self._execution_lock:
            standalone = self._active_execution is None
            if standalone:
                execution = self.begin_execution(spec["mission_id"])
            elif self._active_mission != spec["mission_id"] or self._execution_thread != threading.get_ident():
                raise RuntimeError("project remote belongs to a different active execution")
        try:
            return self._project_remote(action, policy, spec, cwd, target, body, transcript, timeout,
                                        reviews=reviews, previous_head=previous_head)
        finally:
            if standalone:
                self.end_execution(execution)

    def _project_remote(self, action, policy, spec, cwd, target, body, transcript, timeout, *, reviews=None, previous_head=None):
        # Trusted Controller worker; development agents never receive this env.
        from .adapters import FootballPredictionAdapter
        from .factory_test_service import ExecutionStopped
        deadline = time.monotonic() + timeout
        # Startup, work, result delivery and reaping share the original total.
        # Only a normally exited worker can confirm a CI waiting TIMEOUT.
        reserve = min(1.0, timeout / 4)
        worker_deadline, response_deadline = deadline - reserve, deadline - reserve / 2
        cancel = self.container_cancel
        env = FootballPredictionAdapter._trusted_subprocess_environment(env={"LANG": "C.UTF-8"})
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
        stderr = transcript.with_suffix(".stderr")
        argv = [sys.executable, "-m", "harness.factory_remote"]
        with stderr.open("xb") as errors:
            os.fchmod(errors.fileno(), 0o600)
            with self._execution_lock:
                if cancel.is_set() or self.container_cancel is not cancel:
                    raise ExecutionStopped("CANCELLED")
                if time.monotonic() >= worker_deadline:
                    raise subprocess.TimeoutExpired(argv, timeout)
                proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                    text=True, cwd=transcript.parent, env=env, start_new_session=True)
                self.current_process = proc
            completed = False
            try:
                message = json.dumps({"action": action, "policy": policy, "spec": spec,
                    "cwd": str(cwd), "target": target, "body": body, "transcript": str(transcript),
                    "timeout": timeout, "deadline": worker_deadline, "reviews": reviews, "previous_head": previous_head})
                while True:
                    if cancel.is_set() or self.container_cancel is not cancel:
                        raise ExecutionStopped("CANCELLED")
                    remaining = response_deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    try:
                        output, _ = proc.communicate(message, timeout=min(0.05, remaining))
                        completed = True
                        break
                    except subprocess.TimeoutExpired:
                        message = None  # communicate retains the unsent input/output.
                if cancel.is_set():
                    raise ExecutionStopped("CANCELLED")
                if proc.returncode:
                    raise RuntimeFailure("project PR/CI worker failed; outcome retained as UNKNOWN, no replay")
                return json.loads(output)
            finally:
                try:
                    if not completed or proc.poll() is None:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
                finally:
                    try:
                        for stream in (proc.stdin, proc.stdout):
                            if stream is not None:
                                try:
                                    stream.close()
                                except BrokenPipeError:
                                    pass
                    finally:
                        with self._execution_lock:
                            if self.current_process is proc and proc.poll() is not None:
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
    def __init__(self, message, usage=None, identity=None, *, usage_complete=False, usage_telemetry=None):
        self.usage, self.identity = usage, identity
        self.usage_complete = usage_complete
        self.usage_telemetry = usage_telemetry
        super().__init__(message)

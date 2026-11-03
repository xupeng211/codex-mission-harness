"""Thin, bounded execution adapters. Codex owns coding and review intelligence."""
from __future__ import annotations

from dataclasses import dataclass
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

from .adapters import GateResult
from .codex import AppServerCodex
from .appserver_process import AppServerProcess, process_identity, validate_supervised_stop
from .task_temp import TaskTemp, TaskTempError
from .model_registry import read_private_token
from .sandbox import project_gate_invocation, preflight_project_gate, SAFE_PATH
from .factory_proxy import validate_transport, ProxyPolicy, ProxyRelay, digest as route_digest
from .factory_project import FootballPredictionContract, LANES


@dataclass(frozen=True)
class SupervisedReviewResult(GateResult):
    """Controller lifecycle references; canonical receipt data stays unchanged."""
    validation_lifecycle: dict | None = None
    validation_evidence: tuple = ()


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
                 protected_paths: tuple[Path, ...] = (), execution_context=None, owner_callback=None):
        self._execution_context = execution_context
        self._owner_callback = owner_callback
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
        self._task_temp = None
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
        # Preserve workspace-profile metadata protection without inheriting its
        # grants to the host's shared /tmp and caller-selected TMPDIR.
        for name in (".agents", ".codex", ".aws"):
            rules[str(cwd / name)] = "read"
        # Both lanes start from the existing minimal repository/runtime boundary.
        overrides = [
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
            if not read_only:
                forbidden = [*denied_roots, Path(home), Path(self._source_home)]
                if self.transport["type"] == "cli_proxy":
                    forbidden.append(Path(self.transport["policy_file"]).parent)
                self._task_temp = TaskTemp(self._policy_cwd, self._permissions_profile, forbidden,
                                           record=transcript.with_suffix(".temp.json"))
                rules.update(self._task_temp.permission_rules())
                # Repeated CLI overrides of the *same* inline table replace it.
                # Emit one complete table, retaining all protected subpaths.
                key = f"permissions.{self._permissions_profile}.filesystem="
                index = next(i for i, item in enumerate(overrides) if item.startswith(key))
                overrides[index] = key + "{" + ",".join(f"{json.dumps(k)}={json.dumps(v)}" for k, v in rules.items()) + "}"
                overrides.extend(self._task_temp.environment_overrides())
                self._native_identity["temporary_workspace"] = self._task_temp.identity
            with transcript.with_suffix(".stderr").open("xb") as stderr:
                # The installed timeout supplies a wall-clock watchdog independent of
                # this controller; unknown dispatch stays charged/unreplayed.
                environment = self._app_server_environment(str(executable), str(cwd), codex_home=home)
                if self._task_temp is not None:
                    environment.update(self._task_temp.environment())
                if self.transport["type"] == "cli_proxy":
                    # Codex talks only to the local observer. Upstream network
                    # routing belongs to the explicit dedicated proxy config.
                    environment = {k:v for k,v in environment.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
                    environment["NO_PROXY"] = "127.0.0.1,localhost,::1"
                self._start_process([str(watchdog), "--signal=TERM", "--kill-after=5", str(timeout),
                                             str(executable), *overrides, "app-server", "--stdio"],
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=stderr, text=True, bufsize=1, cwd=cwd, start_new_session=True,
                                             env=environment, record=transcript.with_suffix(".process.jsonl"))
                self._native_identity["process_ownership"] = {
                    "binding": self._execution.binding, "supervisor": self._execution.identity}
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
        if deadline is not None:
            deadline = min(deadline, self._deadline())
        message = super()._read_message(deadline)
        self.events.append(message)
        self._observe_execution_event(message)
        return message

    def _bind_usage_thread(self, thread_id):
        previous = getattr(self, "_usage_thread_id", None)
        if previous is not None and not (getattr(self, "_reuse_session", False) and previous == thread_id):
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
                "scope": ("one authorized turn in the same explicitly reused thread"
                          if getattr(self, "_reuse_session", False) else "one fresh thread and one authorized turn"),
                "provider_total_usage": "UNKNOWN", "cross_thread_aggregation": "NOT_PERFORMED"}

    def _usage_failure(self, reason, attribution=None):
        if attribution is not None:
            self._usage_scope_errors.append(attribution)
        raise RuntimeFailure(reason, self.usage, self.runtime_identity,
                             usage_telemetry=self.usage_telemetry())

    def _accept_root_usage(self, usage):
        from .factory_budget import tokens
        count = tokens(usage)
        baseline = tokens(getattr(self, "_turn_usage_baseline", None)) or 0
        if count is None or count < baseline:
            self._usage_failure("native usage is not a valid attributed token count")
        self.usage = usage
        if self.token_limit and count - baseline > self.token_limit:
            if not getattr(self, "_reuse_session", False):
                self._usage_failure("Codex token telemetry exceeded run allowance")
            if not getattr(self, "_budget_exceeded", False):
                # Main's same-thread repair path drains the terminal event
                # after interrupt; cumulative snapshots are charged as deltas.
                self._budget_exceeded = True
                self._end_time = min(self._end_time, time.monotonic() + 5)
                self.seq += 1
                try:
                    self.proc.stdin.write(json.dumps({"id": self.seq, "method": "turn/interrupt",
                        "params": {"threadId": self._usage_thread_id, "turnId": self._usage_turn_id}}) + "\n")
                    self.proc.stdin.flush()
                except OSError:
                    pass

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
        if method in {"thread/start", "thread/resume"}:
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
            if self.REASONING_EFFORT and result.get("reasoningEffort") != self.REASONING_EFFORT:
                raise RuntimeError("Codex runtime selected a different configured reasoning effort")
        return result

    def _thread_policy_params(self, cwd):
        params = super()._thread_policy_params(cwd)
        if self.MODEL is None:
            params.pop("model")
        params["modelProvider"] = self._transport_provider
        # Native thread/resume requires a stored rollout, including when the
        # same app-server process stays alive. Single-agent repair must retain
        # that history; independent one-shot lanes can remain ephemeral.
        if not getattr(self, "_reuse_session", False):
            params["ephemeral"] = True
        if self.reviewer:
            params["baseInstructions"] = official_rubric()
        # Disable remote tools; their independent authority is outside this local factory.
        params["config"]["mcp_servers"] = self.disabled_mcp
        features = {"hooks": False, "apps": False, "multi_agent": False, "multi_agent_v2": False}
        if self.token_limit:
            features["rollout_budget"] = {
                "enabled": True, "limit_tokens": self.token_limit,
                "reminder_at_remaining_tokens": [max(1, self.token_limit // 4)],
                "sampling_token_weight": 1.0, "prefill_token_weight": 1.0}
        params["config"]["features"] = features
        params["config"]["agents"] = {"enabled": False}
        params["config"]["project_root_markers"] = []
        return params

    def start_or_resume(self, thread_id, cwd):
        if thread_id and getattr(self, "_reuse_session", False):
            # A subscribed loaded thread ignores resume config overrides. Drop
            # this connection's subscription so the idle thread can be rebuilt
            # from its stored history with the repair budget/permissions. Keep
            # the same thread ID and process; never start a replacement thread.
            result = self._request("thread/unsubscribe", {"threadId": thread_id})
            if not isinstance(result, dict) or result.get("status") not in {"unsubscribed", "notSubscribed", "notLoaded"}:
                raise RuntimeError("Codex thread unsubscribe was not confirmed; no repair dispatch")
        resumed = super().start_or_resume(thread_id, cwd)
        if thread_id and resumed != thread_id:
            raise RuntimeError("Codex changed the execution thread; no repair dispatch")
        return resumed

    def execute(self, prompt: str, schema: dict, thread_id: str | None = None, return_thread: bool = False) -> dict:
        self._turn_usage_baseline = getattr(self, "_native_usage_snapshot", self.usage)
        self._usage_complete = False
        self._active_thread_id = None
        self._budget_exceeded = False
        thread_id = self.start_or_resume(thread_id, self._policy_cwd)
        self._active_thread_id = thread_id
        # Usage may arrive before the turn/start response. Its explicit turnId
        # is authoritative until that response binds the accepted turn below.
        if hasattr(self, "_active_turn_id"):
            del self._active_turn_id
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
        self._active_turn_id = turn_id
        self.runtime_identity.update(thread_id=thread_id, turn_id=turn_id)
        completed = self._turn_completed(thread_id, turn_id, require_success=False)
        self.runtime_identity["turn_completion"] = completed
        if completed.get("status") != "completed":
            # Cancellation/failed inference may have unreported in-flight usage.
            # Preserve terminal identity without releasing its unknown reserve.
            raise RuntimeFailure("Codex turn ended with status " + str(completed.get("status")),
                                 self.usage, self.runtime_identity)
        routed = [e["params"] for e in self.events if e.get("method") == "model/rerouted" and e.get("params", {}).get("threadId") == thread_id]
        if self.MODEL and any(e.get("toModel") != self.MODEL for e in routed):
            raise RuntimeError("explicit configured model was rerouted; exact model identity changed")
        self.runtime_identity.update(thread_id=thread_id, turn_id=turn_id, model_routing=routed)
        items = {i["id"]: i for i in completed.get("items", []) if "id" in i}
        turn_usage = []
        for event in self.events:
            p = event.get("params", {})
            if p.get("threadId") == thread_id and p.get("turnId") == turn_id:
                if event.get("method") == "item/completed":
                    item = p.get("item", {})
                    if "id" in item:
                        items[item["id"]] = item
                if event.get("method") == "thread/tokenUsage/updated":
                    turn_usage.append(p.get("tokenUsage"))
        if not turn_usage or any(value is None for value in turn_usage):
            raise RuntimeFailure("turn usage telemetry missing or incomplete; no replay", self.usage, self.runtime_identity)
        from .factory_budget import tokens
        if any(tokens(value) is None for value in turn_usage):
            raise RuntimeFailure("turn usage telemetry invalid; no replay", turn_usage[-1], self.runtime_identity)
        from .factory_candidate import usage_increment
        previous = self._turn_usage_baseline
        for value in turn_usage:
            if usage_increment(value, previous.get("total", previous) if previous else None) is None:
                raise RuntimeFailure("turn usage telemetry regressed or changed shape; no replay", value, self.runtime_identity)
            previous = value
        self.usage = turn_usage[-1]
        self._native_usage_snapshot = self.usage
        self._usage_complete = not getattr(self, "_proxy_relay", None)
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
                "thread_id": thread_id if return_thread else None, "turn_id": turn_id,
                "turn_completion": completed, "usage_complete": True,
                "usage_events": turn_usage,
                "usage_telemetry": self.usage_telemetry(),
                "runtime_identity": self.runtime_identity, "model_routing": routed,
                **({"physical_accounting": receipt, "usage_complete": receipt["usage_complete"]} if receipt else {})}

    def close(self):
        try:
            super().close()
        finally:
            relay = getattr(self, "_proxy_relay", None)
            if relay:
                relay.close()
                sources = {self.transcript.with_suffix(".stderr")}
                if hasattr(self, "_session_stderr"):
                    sources.add(self._session_stderr)
                for error in sources:
                    if error.exists():
                        error.write_bytes(error.read_bytes().replace(relay.nonce.encode(), b"[REDACTED]"))
                self._proxy_relay = None
            home = getattr(self, "_proxy_home", None)
            if home and getattr(self, "_process_stop", {}).get("confirmed") is True:
                home.cleanup()
                self._proxy_home = None


class LocalRuntime:
    """Codex turns + existing bubblewrap gates + a separate DeepSeek API lane."""

    simulation = False

    def __init__(self):
        import threading
        self.resource_policy = {}
        self.current_process = None
        self._validation_cancelled = False
        self._single_server = None
        self._single_binding = None
        self._review_owner = None
        self._remote_worker = None
        # The gate's sequential owned-client slot covers preparation and the
        # main validation client; retain the existing slot name for callers.
        self._preparation_client = None
        self._preparation_cleanups = []
        self.container_cancel = threading.Event()
        self._execution_lock = threading.RLock()
        self._active_execution = self._active_mission = None
        self._execution_id = None
        self._execution_thread = None

    def close_session(self):
        server = self._single_server
        cleanup = None
        if server is not None:
            server.close()
            cleanup = getattr(server, "_task_temp_cleanup", None)
            if cleanup and server._task_temp.cleanup_log is not None:
                path = server._task_temp.cleanup_log
                try:
                    receipt_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                    allocation = server._task_temp._record
                    allocation_hash = hashlib.sha256(allocation.read_bytes()).hexdigest()
                except OSError as error:
                    # Retain runtime ownership until both deletion and its proof
                    # are confirmed; another task cannot inherit this session.
                    raise TaskTempError("task temporary cleanup receipt is unconfirmed: " + str(path),
                                        server._task_temp.identity) from error
                cleanup = {**cleanup, "evidence": {"path": str(path), "sha256": receipt_hash},
                           "allocation": {"path": str(allocation), "sha256": allocation_hash}}
            if self.current_process is server.proc:
                self.current_process = None
        self._single_server = None
        self._single_binding = None
        return cleanup

    def unconfirmed_appserver(self):
        if self._review_owner is not None:
            return "canonical review process stop/evidence UNKNOWN; no replacement execution"
        if self._single_server is not None:
            # This slot is released only after both shutdown and its complete
            # cleanup receipt are accepted, including receipt-read failures.
            return "AppServer still owns this runtime; stop/cleanup is unconfirmed or active; no replacement execution"
        return None

    def begin_execution(self, mission):
        import threading
        with self._execution_lock:
            if self._active_execution is not None or self.current_process is not None or self._single_server is not None or self._review_owner is not None:
                raise RuntimeError("runtime already belongs to an active execution")
            # A new identity, not clearing an old task's cancellation latch.
            self.container_cancel = threading.Event()
            self._validation_cancelled = False
            self._preparation_cleanups = []
            self._active_execution, self._active_mission = self.container_cancel, mission
            self._execution_id = uuid.uuid4().hex
            self._execution_thread = threading.get_ident()
            return self._active_execution

    def end_execution(self, execution):
        with self._execution_lock:
            if execution is self._active_execution:
                # An unconfirmed owned group still owns this execution. Even
                # Factory.run's outer finally must not admit a new execution.
                if (self._remote_worker is not None or self._preparation_client is not None
                        or self._single_server is not None or self.current_process is not None
                        or self._review_owner is not None):
                    return False
                self._active_execution = self._active_mission = None
                self._execution_id = None
                self._execution_thread = None
                return True

    def cancel(self, execution=None):
        with self._execution_lock:
            if execution is None:
                if self._active_execution is not None:
                    return False  # Factory watchers must supply their execution identity.
            elif execution is not self._active_execution:
                return False  # A delayed callback cannot affect a later mission/run.
            self._validation_cancelled = True
            self.container_cancel.set()
            proc = self.current_process
            client = self._remote_worker if self._remote_worker is not None else self._preparation_client
            if self._review_owner is not None:
                return True  # Owner loop observes the latch; never poll/reap/kill its anchor.
            if client is not None:
                try:
                    self._signal_owned_client(client, signal.SIGTERM)
                except Exception as error:
                    # The event still cancels work; the owning call performs
                    # bounded cleanup and records any failure. Never reap the
                    # group leader here via Popen.poll().
                    client["cancel_error"] = f"{type(error).__name__}: {error}"
            elif self._single_server is not None:
                try:
                    self._single_server._stop_execution()
                except TaskTempError:
                    # Keep the server, TaskTemp and execution slot. Its owning
                    # finally records UNKNOWN; cancellation must not reap a
                    # leader or signal an old PGID as a fallback.
                    pass
            elif proc is not None and proc.poll() is None:
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
        dependencies = ["codex.py", "appserver_process.py", "task_temp.py", "factory_proxy.py", "factory_routing.py"] if profile["provider"] == "openai" else ["factory_http.py", "model_registry.py"]
        identity["transport_hashes"] = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in dependencies}
        return identity

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        if self.container_cancel.is_set():
            raise RuntimeFailure("execution cancelled before AppServer dispatch; no replay", None, None)
        authorized_route = payload.pop("_authorized_route", None)
        if authorized_route is not None and self.profile_identity(profile).get("route_identity") != authorized_route:
            raise RuntimeFailure("task route differs from authorization; no dispatch", None, None)
        thread_id = payload.pop("_thread_id", None)
        return_thread = bool(payload.pop("_return_thread", False))
        reuse_session = bool(payload.pop("_reuse_session", False))
        token_limit = self.resource_policy.get("max_run_tokens")
        operation_limit = payload.pop("_operation_token_limit", None)
        if operation_limit is not None:
            from .factory_budget import operation_token_limit
            expected = operation_token_limit(self.resource_policy, role, local_candidate=True)
            if operation_limit != expected:
                raise RuntimeFailure("operation token limit differs from verified stage authority", None, None)
            token_limit = operation_limit
        if role == "plan":
            from .factory_budget import planning_limits
            limits = planning_limits(self.resource_policy, timeout)
            token_limit, timeout = limits["max_tokens"], limits["timeout_seconds"]
            payload = {**payload, "planning_resource_guard": {
                **limits, "physical_token_ceiling": "NOT_GUARANTEED",
                "instruction": "Use targeted searches and small excerpts. Do not dump the repository, generated bundles or unrelated documentation. Stop exploring once you can return a bounded actionable plan; if essential information is missing, state the unresolved decision. Do not repeat broad scans."}}
        protected = (cwd / payload["mission_scope_file"],) if payload.get("mission_scope_file") else ()
        binding = (json.dumps(profile, sort_keys=True), str(cwd.resolve()), tuple(map(str, denied_roots)))
        if reuse_session and self._single_server is not None:
            if self._single_binding != binding:
                raise RuntimeFailure("single-agent App Server binding changed; no replay", None, None)
            server = self._single_server
            server._validate_task_temp()
            server.transcript = transcript
            server._transcript_bytes = 0
            server._response_timeout = timeout
            server._end_time = time.monotonic() + timeout
            server.token_limit = token_limit
            if server._proxy_relay:
                server._proxy_relay.start_turn(transcript, timeout, token_limit)
            if hasattr(server, "_native_identity"):
                server._native_identity["execution_limits"]["token_limit"] = token_limit
        else:
            def retain_owner(owner):
                with self._execution_lock:
                    self._single_server, self._single_binding = owner, binding
                    self.current_process = owner.proc
                    if self.container_cancel.is_set():
                        owner._stop_execution()
            try:
                server = FactoryAppServer(profile, cwd, transcript, timeout, denied_roots,
                                          role in ("plan", "review"), role == "review", token_limit,
                                          protected_paths=protected,
                                          execution_context={"mission_id": self._active_mission,
                                                             "runtime_execution": self._execution_id},
                                          owner_callback=retain_owner)
            except BaseException as error:
                owner = getattr(error, "owner", self._single_server)
                if owner is not None:
                    if (getattr(owner, "_process_stop", {}).get("confirmed") is True
                            and (getattr(owner, "_task_temp", None) is None
                                 or getattr(owner, "_task_temp_cleanup", {}).get("cleanup_confirmed") is True)):
                        self._single_server = self._single_binding = self.current_process = None
                    else:
                        self._single_server, self._single_binding = owner, binding
                        self.current_process = getattr(owner, "proc", None)
                raise
            # Non-reused servers also own this slot until their close proves
            # quiescence. This includes initialization/EOF/cancel failures.
            self._single_server, self._single_binding = server, binding
            if reuse_session:
                errors = transcript.with_suffix(".stderr")
                if errors.exists():
                    # The child keeps this inode open across turns. Snapshot
                    # it per operation so repair cannot alter first-turn hashes.
                    server._session_stderr = transcript.with_suffix(".process-stderr")
                    errors.rename(server._session_stderr)
                    server._stderr_offset = 0
        if authorized_route is not None and (not server._proxy_relay or
                server._proxy_relay.policy.identity != authorized_route.get("runtime")):
            server.close()
            self._single_server = self._single_binding = None
            raise RuntimeFailure("proxy runtime changed before dispatch; new authorization required", None, None)
        self.current_process = server.proc
        server._reuse_session = reuse_session
        try:
            schema = REVIEW_SCHEMA if role == "review" else PLAN_SCHEMA if role == "plan" else WORK_SCHEMA
            result = server.execute(json.dumps(payload, ensure_ascii=False), schema,
                                    thread_id=thread_id, return_thread=return_thread)
            if not return_thread:
                result.pop("thread_id", None)
            return result
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
                                 usage_complete=getattr(server, "_usage_complete", False),
                                 usage_telemetry=server.usage_telemetry()) from exc
        finally:
            if reuse_session and hasattr(server, "_session_stderr"):
                data = server._session_stderr.read_bytes()
                chunk = data[server._stderr_offset:]
                server._stderr_offset = len(data)
                if server._proxy_relay:
                    chunk = chunk.replace(server._proxy_relay.nonce.encode(), b"[REDACTED]")
                with transcript.with_suffix(".stderr").open("xb") as errors:
                    os.fchmod(errors.fileno(), 0o600)
                    errors.write(chunk)
            if not reuse_session:
                try:
                    server.close()
                except TaskTempError:
                    # Keep the exact resource available to Factory's cleanup
                    # finally; an unconfirmed session cannot pass to a new task.
                    self._single_server, self._single_binding = server, binding
                    raise
                self._single_server = self._single_binding = None
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
            if self._remote_worker is not None or self._preparation_client is not None:
                raise RuntimeFailure("unconfirmed client cleanup blocks another container gate")
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

    def _supervised_review_step(self, binding, argv, cwd, environment, transcript, timeout, *, stdin=None):
        """Reuse the existing task Controller's per-operation subreaper sequence."""
        if self._review_owner is not None or self.container_cancel.is_set():
            raise RuntimeFailure("canonical lifecycle occupied or cancelled; no dispatch")
        transcript = Path(transcript)
        journal = transcript.with_suffix(transcript.suffix + ".process.jsonl")
        stop_path = transcript.with_suffix(transcript.suffix + ".stop.json")
        owner = AppServerProcess(binding, record=journal)
        self._review_owner = owner
        outcome = "complete"
        try:
            with transcript.open("xb") as out, transcript.with_suffix(transcript.suffix + ".stderr").open("xb") as err:
                os.fchmod(out.fileno(), 0o600); os.fchmod(err.fileno(), 0o600)
                owner.start(argv, cwd=str(cwd), env=environment,
                            stdin=stdin if stdin is not None else subprocess.DEVNULL, stdout=out, stderr=err)
                deadline = time.monotonic() + timeout
                while True:
                    actual = process_identity(owner.payload["pid"])
                    if any(actual[k] != owner.payload[k] for k in ("pid", "ppid", "uid", "starttime")):
                        raise RuntimeError("canonical payload identity changed")
                    if self.container_cancel.is_set():
                        outcome = "cancelled"; break
                    if actual["state"] in ("Z", "X"):
                        break
                    if time.monotonic() >= deadline:
                        outcome = "timeout"; break
                    time.sleep(.02)
        except BaseException:
            outcome = "failed"
            raise
        finally:
            # Even timeout/cancel/fault must stop only this allocation's tree.
            stop = owner.stop()
            matches = [v for v in stop.get("reaped", []) if v["pid"] == owner.payload["pid"]]
            if len(matches) != 1:
                raise RuntimeFailure("canonical payload exit UNKNOWN; retained supervision")
            code = os.waitstatus_to_exitcode(matches[0]["status"])
            doc = {"binding": owner.binding, "supervisor": owner.identity, "payload": owner.payload,
                   "supervisor_exit": owner.proc.returncode, "stop": stop, "exit_code": code,
                   "outcome": outcome, "journal": str(journal),
                   "journal_sha256": hashlib.sha256(journal.read_bytes()).hexdigest()}
            with stop_path.open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(doc, sort_keys=True)); stream.flush(); os.fsync(stream.fileno())
            reference = {"path": str(stop_path), "sha256": hashlib.sha256(stop_path.read_bytes()).hexdigest()}
            validate_supervised_stop(reference, binding, outcome=outcome)
            # Clear only after the full original stop record is durable. On
            # UNKNOWN, owner/evidence remain attached and no new step may start.
            self._review_owner = None
        if outcome != "complete":
            raise RuntimeFailure("canonical operation " + outcome + "; no verdict consumed")
        return code, reference

    def project_review(self, spec, cwd, target, lane, transcript, timeout, *, prepared=None):
        from .factory_project import review_process_binding
        contract = FootballPredictionContract()
        if isinstance(prepared, dict):
            admission = contract.review_admission(spec, cwd, target, prepared["admission"]["authorization"])
            if admission != prepared["admission"]:
                raise ValueError("canonical diff/chunk admission changed before dispatch")
            prepared = prepared["runner"]
        argv, evidence, environment = prepared if prepared is not None else self.prepare_project_review(
            spec, cwd, target, lane, timeout)
        contract.adapter._validate_review_evidence_dir(evidence)
        transcript = Path(transcript)
        result = {"stdout_path": str(transcript), "stderr_path": str(transcript.with_suffix(".review.stderr")),
                  "evidence_dir": str(evidence), "fixture": False,
                  "executed_runner_argv": argv, "usage": None, "usage_complete": False}
        binding = review_process_binding(spec, cwd, target, lane, result)
        review_log = transcript.with_suffix(".review")
        code, reference = self._supervised_review_step(binding, argv, cwd, environment, review_log, timeout)
        # Canonical stdout remains the operation's stable raw artifact. Preserve
        # review logs rather than rename the files named by stop provenance.
        with transcript.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600); stream.write(review_log.read_bytes())
        result.update(exit_code=code, review_lifecycle=reference)
        result["project_evidence"] = [{"path": str(path.resolve()),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in evidence.iterdir() if path.is_file() and not path.is_symlink()]
        for path in (review_log, review_log.with_suffix(".review.stderr"),
                     review_log.with_suffix(".review.process.jsonl"), Path(reference["path"])):
            result["project_evidence"].append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        checked = self.project_validate_review(spec, cwd, target, lane, result)
        result["validation_lifecycle"] = checked.validation_lifecycle
        result["project_evidence"].extend(checked.validation_evidence)
        result["canonical_receipt"] = checked.artifact
        return result

    def project_validate_review(self, spec, cwd, target, lane, result):
        from .factory_project import validate_review_stop, verify_target
        validate_review_stop(spec, cwd, target, lane, result)
        verify_target(spec, cwd, target)
        # Each revalidation has a fresh unpaid operation; it cannot re-sign the
        # original runner proof or replay a paid reviewer. Keep every original.
        log = Path(result["stdout_path"]).with_suffix(".validator-" + uuid.uuid4().hex)
        request = log.with_suffix(log.suffix + ".input.json")
        value = {"spec": spec, "cwd": str(cwd), "target": target, "lane": lane, "result": result}
        with request.open("x") as stream:
            os.fchmod(stream.fileno(), 0o600); json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
        code = ("import sys,json; from dataclasses import asdict; sys.path.insert(0,sys.argv[1]); "
                "from harness.factory_project import FootballPredictionContract; "
                "v=json.load(sys.stdin); r=FootballPredictionContract().validate_review("
                "v['spec'],v['cwd'],v['target'],v['lane'],v['result']); print(json.dumps(asdict(r)))")
        argv = [sys.executable, "-I", "-B", "-c", code, str(Path(__file__).resolve().parents[1])]
        snapshot = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in (Path(result["stdout_path"]), Path(result["stderr_path"]))}
        for raw in result.get("project_evidence", []):
            snapshot[raw["path"]] = raw["sha256"]
        binding = {"stage": "canonical-validator", "mission": spec["mission_id"], "target": target,
                   "lane": lane, "operation": result["stdout_path"], "argv": argv,
                   "review_lifecycle": result["review_lifecycle"], "inputs": snapshot,
                   "request_sha256": hashlib.sha256(request.read_bytes()).hexdigest()}
        environment = FootballPredictionContract().adapter.review_environment(
            "deepseek", worktree=str(cwd), base=target["base"])
        with request.open("rb") as stream:
            status, proof = self._supervised_review_step(binding, argv, cwd, environment, log, 60, stdin=stream)
        if status != 0:
            raise RuntimeFailure("canonical validator did not establish a verdict; evidence retained")
        validate_review_stop(spec, cwd, target, lane, result)
        verify_target(spec, cwd, target)
        if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest for path, digest in snapshot.items()):
            raise RuntimeFailure("canonical evidence changed during validation")
        artifacts = tuple({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in (request, log, log.with_suffix(log.suffix + ".stderr"),
                         log.with_suffix(log.suffix + ".process.jsonl"), Path(proof["path"])))
        return SupervisedReviewResult(**json.loads(log.read_text()),
                                      validation_lifecycle=proof, validation_evidence=artifacts)

    def project_validation(self, policy, spec, command, cwd, target, transcript, timeout):
        from .factory_validation import run
        return run(policy, spec, cwd, target, command, transcript, timeout,
                   cancelled=lambda: self._validation_cancelled)

    def project_ci(self, policy, spec, cwd, target, approval, transcript, timeout):
        from .factory_pr_ci import run
        return run(policy, spec, cwd, target, approval, transcript, timeout,
                   cancelled=lambda: self._validation_cancelled)

    def project_validate_ci(self, policy, spec, cwd, target, result, refresh=False):
        from .factory_pr_ci import GitHub, validate_result
        # Reconciliation is read-only. Its log is retained alongside original
        # evidence but never substitutes for the immutable operation record.
        path = cwd.parent / ("pr-ci-recheck-" + uuid.uuid4().hex + ".jsonl")
        api = GitHub(cwd, path, 60) if refresh else None
        return validate_result(result, policy, spec, cwd, target, self.simulation, api)

    def project_final_gate(self, spec, cwd, target, reviews, transcript, timeout, *, context=None):
        if context is not None and "policy" in context:
            return self.project_remote("verify", context["policy"], spec, cwd, target,
                                       context["body"], transcript, timeout, reviews=reviews)
        if context is not None:
            from .factory_project import validate_review_stop, verify_target
            executions = {r["lane"]: r["canonical_execution"] for r in reviews}
            for lane, result in executions.items():
                validate_review_stop(spec, cwd, target, lane, result)
            verify_target(spec, cwd, target)
            request = Path(transcript).with_suffix(".input.json")
            value = {"spec": spec, "cwd": str(cwd), "target": target,
                     "receipts": {LANES[r["lane"]]: r["canonical_receipt"] for r in reviews},
                     "context": context, "executions": executions}
            with request.open("x") as stream:
                os.fchmod(stream.fileno(), 0o600); json.dump(value, stream)
            code = ("import sys,json; from dataclasses import asdict; sys.path.insert(0,sys.argv[1]); "
                    "from harness.factory_project import FootballPredictionContract; "
                    "r=FootballPredictionContract().final_gate(**json.load(sys.stdin)); print(json.dumps(asdict(r)))")
            argv = [sys.executable, "-I", "-B", "-c", code, str(Path(__file__).resolve().parents[1])]
            binding = {"stage": "canonical-final-gate", "mission": spec["mission_id"], "target": target,
                       "argv": argv, "request_sha256": hashlib.sha256(request.read_bytes()).hexdigest()}
            environment = FootballPredictionContract().adapter.review_environment("deepseek", worktree=str(cwd), base=target["base"])
            with request.open("rb") as stream:
                status, proof = self._supervised_review_step(binding, argv, cwd, environment, transcript, timeout, stdin=stream)
            if status != 0:
                raise RuntimeFailure("canonical final consumer unconfirmed; retained evidence")
            verify_target(spec, cwd, target)
            gate = json.loads(Path(transcript).read_text())
            return {"status": gate["status"], "reason": gate["evidence"], "target": target,
                    "fixture": False, "canonical_gate": gate["data"], "validation_lifecycle": proof,
                    "project_evidence": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                        for path in (request, Path(proof["path"]), Path(transcript).with_suffix(Path(transcript).suffix + ".process.jsonl"))]}
        receipts = {LANES[r["lane"]]: r["canonical_receipt"] for r in reviews}
        gate = FootballPredictionContract().final_gate(spec, cwd, target, receipts, context)
        result = {"status": gate.status, "reason": gate.evidence, "target": target, "fixture": False,
                  "canonical_gate": gate.data}
        transcript.write_text(json.dumps(result))
        evidence = cwd.parent / ".cmh-merge-evidence" / spec.get("mission_id", "") / target["head"]
        if evidence.is_dir():
            artifacts = []
            for p in evidence.iterdir():
                if p.is_file() and not p.is_symlink():
                    copy = transcript.parent / (transcript.stem + "-merge-" + p.name)
                    with copy.open("xb") as stream:
                        stream.write(p.read_bytes())
                    copy.chmod(0o400)
                    artifacts.append({"path": str(copy), "sha256": hashlib.sha256(copy.read_bytes()).hexdigest()})
            result["project_evidence"] = artifacts
        return result

    def project_remote(self, action, policy, spec, cwd, target, body, transcript, timeout, *, reviews=None, previous_head=None):
        import threading
        with self._execution_lock:
            standalone = self._active_execution is None
            if standalone:
                execution = self.begin_execution(spec["mission_id"])
            elif self._active_mission != spec["mission_id"] or self._execution_thread != threading.get_ident():
                raise RuntimeError("project remote belongs to a different active execution")
            if self._remote_worker is not None or self._preparation_client is not None:
                raise RuntimeFailure("unconfirmed client cleanup blocks another dispatch")
        try:
            return self._project_remote(action, policy, spec, cwd, target, body, transcript, timeout,
                                        reviews=reviews, previous_head=previous_head)
        finally:
            if standalone:
                self.end_execution(execution)

    @staticmethod
    def _client_process_identity(pid):
        """Linux metadata only; no process environment or command contents."""
        return process_identity(pid)

    def _owned_client_leader(self, worker):
        # All callers hold _execution_lock. A direct child observed with
        # WNOWAIT remains unreaped: the kernel cannot reuse its PID/PGID. No
        # communicate/poll/wait is allowed until group shutdown is confirmed.
        proc, expected = worker["process"], worker["identity"]
        if ((self._remote_worker is not worker and self._preparation_client is not worker)
                or self.current_process is not proc
                or self._active_execution is not worker["execution"] or proc.returncode is not None):
            raise RuntimeFailure("controlled client ownership is no longer current")
        exited = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        actual = self._client_process_identity(proc.pid)
        if (expected is None or any(actual[k] != expected[k] for k in expected if k != "state")
                or actual["ppid"] != os.getpid() or actual["uid"] != os.geteuid()
                or actual["pgid"] != proc.pid or actual["sid"] != proc.pid):
            raise RuntimeFailure("controlled client identity/owned session cannot be confirmed")
        return exited

    def _owned_client_group(self, worker):
        self._owned_client_leader(worker)
        leader = worker["identity"]
        members = []
        for name in os.listdir("/proc"):
            if not name.isdecimal():
                continue
            try:
                member = self._client_process_identity(int(name))
            except (FileNotFoundError, ProcessLookupError):
                continue
            if member["pgid"] == leader["pgid"]:
                if member["sid"] != leader["sid"] or member["uid"] != leader["uid"]:
                    raise RuntimeFailure("controlled group ownership cannot be confirmed")
                members.append(member)
        self._owned_client_leader(worker)
        return members

    def _signal_owned_client(self, worker, sig):
        with self._execution_lock:
            self._owned_client_group(worker)
            # Recheck the unreaped direct-child anchor immediately before
            # signalling. Never signal this PGID after reaping the leader.
            self._owned_client_leader(worker)
            os.killpg(worker["process"].pid, sig)

    def _finish_remote_worker(self, worker, deadline):
        return self._finish_owned_client(worker, deadline)

    def _finish_owned_client(self, worker, deadline):
        """Shared by the remote worker and this gate's sequential clients."""
        record = {"identity": worker["identity"], "mission": worker["mission"], "confirmed": False, "leader_reaped": False,
                  "members_before": [], "pending_descendant_reap": [], "errors": []}
        if worker.get("cancel_error"):
            record["errors"].append(worker["cancel_error"])
        try:
            with self._execution_lock:
                record["members_before"] = self._owned_client_group(worker)
            if any(p["state"] not in {"Z", "X"} for p in record["members_before"]):
                self._signal_owned_client(worker, signal.SIGKILL)
                record["signal"] = "SIGKILL"
            while True:
                with self._execution_lock:
                    members = self._owned_client_group(worker)
                    if not any(p["state"] not in {"Z", "X"} for p in members):
                        record["pending_descendant_reap"] = [p for p in members if p["pid"] != worker["process"].pid]
                        # The leader is known exited; wait(0) does not create a
                        # new work/cleanup budget. Descendants may await their
                        # own parent/init reaper; they are no longer running.
                        worker["process"].wait(timeout=0)
                        record.update(confirmed=True, leader_reaped=True)
                        self.current_process = None
                        if self._remote_worker is worker:
                            self._remote_worker = None
                        if self._preparation_client is worker:
                            self._preparation_client = None
                        break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("controlled group shutdown unconfirmed within original deadline")
                time.sleep(min(0.01, remaining))
        except Exception as error:
            record["errors"].append(f"{type(error).__name__}: {error}")
            # Keep both the unreaped anchor and execution identity when we
            # cannot safely establish group shutdown. No speculative kill,
            # no new execution, and no claim that cleanup succeeded.
        return record

    def _project_remote(self, action, policy, spec, cwd, target, body, transcript, timeout, *, reviews=None, previous_head=None):
        if action == "verify":
            remote_log = Path(transcript).with_suffix(".remote.jsonl")
            request_value = {"action": action, "policy": policy, "spec": spec, "cwd": str(cwd),
                             "target": target, "body": body, "transcript": str(remote_log),
                             "timeout": timeout, "reviews": reviews, "previous_head": previous_head}
            argv = [sys.executable, "-m", "harness.factory_remote"]
            from .adapters import FootballPredictionAdapter
            environment = FootballPredictionAdapter._trusted_subprocess_environment(env={"LANG": "C.UTF-8"})
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            binding = {"stage": "canonical-final-gate", "mission": spec["mission_id"],
                       "target": target, "argv": argv, "request_sha256": hashlib.sha256(
                           json.dumps(request_value, sort_keys=True).encode()).hexdigest()}
            with tempfile.TemporaryFile() as request:
                request.write(json.dumps(request_value).encode()); request.seek(0)
                code, proof = self._supervised_review_step(
                    binding, argv, Path(transcript).parent, environment, transcript, timeout, stdin=request)
            if code != 0:
                raise RuntimeFailure("canonical final gate failed; supervised evidence retained")
            result = json.loads(Path(transcript).read_text())
            return {**result, "validation_lifecycle": proof, "project_evidence": [
                {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in (remote_log, Path(proof["path"]), Path(transcript).with_suffix(
                    Path(transcript).suffix + ".process.jsonl")) if path.is_file()]}
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
        # Regular private capture files let us observe worker exit WITHOUT
        # communicate() reaping the only kernel ownership anchor. Raw stdout
        # also survives abnormal/partial worker responses for UNKNOWN evidence.
        with stderr.open("xb") as errors, transcript.with_suffix(".stdout").open("xb+") as output, \
                tempfile.TemporaryFile(dir=transcript.parent) as request:
            os.fchmod(errors.fileno(), 0o600)
            os.fchmod(output.fileno(), 0o600)
            request.write(json.dumps({"action": action, "policy": policy, "spec": spec,
                "cwd": str(cwd), "target": target, "body": body, "transcript": str(transcript),
                "timeout": timeout, "deadline": worker_deadline, "reviews": reviews, "previous_head": previous_head}).encode())
            request.seek(0)
            with self._execution_lock:
                if cancel.is_set() or self.container_cancel is not cancel:
                    raise ExecutionStopped("CANCELLED")
                if time.monotonic() >= worker_deadline:
                    raise subprocess.TimeoutExpired(argv, timeout)
                proc = subprocess.Popen(argv, stdin=request, stdout=output, stderr=errors,
                    text=True, cwd=transcript.parent, env=env, start_new_session=True)
                self.current_process = proc
                worker = {"process": proc, "execution": self._active_execution,
                          "mission": spec["mission_id"], "identity": None}
                self._remote_worker = worker
            original_error = None
            try:
                worker["identity"] = self._client_process_identity(proc.pid)
                while True:
                    if cancel.is_set() or self.container_cancel is not cancel:
                        raise ExecutionStopped("CANCELLED")
                    remaining = response_deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    with self._execution_lock:
                        exited = self._owned_client_leader(worker)
                    if exited is not None:
                        break
                    cancel.wait(min(0.05, remaining))
                if cancel.is_set():
                    raise ExecutionStopped("CANCELLED")
                if exited.si_code != os.CLD_EXITED or exited.si_status:
                    raise RuntimeFailure("project PR/CI worker failed; outcome retained as UNKNOWN, no replay")
            except BaseException as error:
                original_error = error
                raise
            finally:
                try:
                    cleanup = self._finish_remote_worker(worker, deadline)
                except Exception as error:
                    # Preserve the original execution exception even if the
                    # cleanup implementation itself unexpectedly fails.
                    cleanup = {"identity": worker["identity"], "mission": worker["mission"],
                        "confirmed": False, "leader_reaped": False,
                        "errors": [f"{type(error).__name__}: {error}"]}
                cleanup["evidence_written"] = False
                try:
                    FootballPredictionAdapter._write_private_file(transcript.with_suffix(".cleanup.json"),
                        json.dumps({k: v for k, v in cleanup.items() if k != "evidence_written"}), exclusive=True)
                    cleanup["evidence_written"] = True
                except Exception as error:
                    detail = f"cleanup evidence {type(error).__name__}: {error}"
                    if error.__cause__ is not None:
                        detail += f"; caused by {type(error.__cause__).__name__}: {error.__cause__}"
                    cleanup["errors"].append(detail)
                if original_error is not None:
                    original_error.remote_cleanup = cleanup
                    if not cleanup["confirmed"] or not cleanup["evidence_written"]:
                        original_error.add_note("remote cleanup/evidence unconfirmed; execution outcome remains UNKNOWN")
                elif not cleanup["confirmed"] or not cleanup["evidence_written"]:
                    error = RuntimeFailure("remote cleanup/evidence unconfirmed; outcome retained as UNKNOWN, no replay")
                    error.remote_cleanup = cleanup
                    raise error
            output.seek(0)
            try:
                if cancel.is_set() or self.container_cancel is not cancel:
                    raise ExecutionStopped("CANCELLED")
                result = json.loads(output.read().decode("utf-8"))
            except Exception as error:
                error.remote_cleanup = cleanup
                raise
            return {**result, "remote_cleanup": cleanup}

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

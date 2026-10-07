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
from pathlib import Path

from .codex import AppServerCodex
from .model_registry import read_private_token
from .sandbox import project_gate_invocation, preflight_project_gate, SAFE_PATH


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
        self.events: list[dict] = []
        self.usage = None
        self.transcript, self._transcript_bytes = transcript, 0
        self._response_timeout = timeout
        self._end_time = time.monotonic() + timeout
        home = self._codex_home(profile.get("codex_home"))
        executable = self._trusted_executable("codex", str(cwd))
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
        # The Git database belongs to the controller, not to coding agents.
        rules[str(cwd / ".git")] = "read"
        # A read-only lane starts with minimal runtime + the exact repository,
        # rather than inheriting the built-in profile's broad host read grant.
        overrides = ([] if read_only else ["-c", f'permissions.{self._permissions_profile}.extends=":workspace"']) + [
                     "-c", f"default_permissions={json.dumps(self._permissions_profile)}",
                     "-c", f"permissions.{self._permissions_profile}.filesystem=" +
                     "{" + ",".join(f"{json.dumps(k)}={json.dumps(v)}" for k, v in rules.items()) + "}",
                     "-c", f"permissions.{self._permissions_profile}.network.enabled=false",
                     "-c", "model_provider=\"openai\"",
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
        with transcript.with_suffix(".stderr").open("xb") as stderr:
            # GNU coreutils supplies a wall-clock watchdog independent of this
            # controller's lifetime; a crashed client cannot leave an unbounded
            # paid Codex loop. Unknown dispatch remains charged and unreplayed.
            self.proc = subprocess.Popen([str(watchdog), "--signal=TERM", "--kill-after=5", str(timeout),
                                          str(executable), *overrides, "app-server", "--stdio"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=stderr,
                                     text=True, bufsize=1, cwd=cwd, start_new_session=True,
                                     env=self._app_server_environment(str(executable), str(cwd), codex_home=home))
        self.seq = 0
        self._pending_messages = []
        self._reader_thread = None
        try:
            self._request("initialize", {"clientInfo": {"name": "software-delivery-factory", "version": "1"},
                                         "capabilities": {"experimentalApi": True}})
            self.proc.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
            self.proc.stdin.flush()
        except BaseException:
            self.close()
            raise

    def _deadline(self) -> float:
        return self._end_time

    def _observe_wire_line(self, line):
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
            self.runtime_identity = {"model": result.get("model"), "provider": result.get("modelProvider"),
                                     "effort": result.get("reasoningEffort"), "profile": self.profile}
            if result.get("modelProvider") != "openai" or not result.get("model"):
                raise RuntimeError("Codex runtime provider/model identity is unproven")
            if self.MODEL and result["model"] != self.MODEL:
                raise RuntimeError("Codex runtime selected a different configured model")
        return result

    def _thread_policy_params(self, cwd):
        params = super()._thread_policy_params(cwd)
        if self.MODEL is None:
            params.pop("model")
        params["modelProvider"] = "openai"
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
        return {"output": json.loads(text[-1]), "usage": self.usage,
                "thread_id": thread_id, "turn_id": turn_id,
                "runtime_identity": self.runtime_identity, "model_routing": routed}

    def close(self):
        proc = getattr(self, "proc", None)
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        super().close()


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
            home = Path(AppServerCodex._codex_home(profile.get("codex_home")))
            selected = [home / "config.toml"]
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
            identity["codex_config_hashes"] = configs
            binary = AppServerCodex._trusted_executable("codex")
            identity["runtime_version"] = subprocess.check_output([str(binary), "--version"], timeout=10, text=True).strip()
        else:
            identity["route"] = "https://api.deepseek.com/chat/completions"
        identity["adapter_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        dependencies = ["codex.py"] if profile["provider"] == "openai" else ["factory_http.py", "model_registry.py"]
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

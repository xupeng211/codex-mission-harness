"""Explicit local CLIProxyAPI route; bounded forwarding and safe wire receipts.

The only supported proxy policy is an owner-controlled, single-credential Docker
instance with retries disabled. The original interactive proxy is never changed.
Proxy telemetry is evidence from the proxy, not independent upstream attestation;
this adapter deliberately does not qualify it as an OpenAI review lane.
"""
from __future__ import annotations

import hashlib
import fcntl
import http.server
import json
import os
import re
import secrets
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from .codex import AppServerCodex
from .model_registry import read_private_token
from .factory_budget import tokens


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def private_file(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("proxy source must be an absolute canonical private file")
    # Reuse the authentication home's ancestor validation, then check the file.
    AppServerCodex._codex_home(str(path.parent))
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("proxy source must be owner-owned mode 0600")
    return path


def validate_transport(profile, reviewer=False):
    transport = profile.get("transport", {"type": "official"})
    if not isinstance(transport, dict) or transport.get("type") not in ("official", "cli_proxy"):
        raise ValueError("transport must explicitly select official or cli_proxy")
    if transport["type"] == "official":
        if set(transport) != {"type"}:
            raise ValueError("official transport does not accept proxy fields")
        return transport
    if set(transport) != {"type", "endpoint", "configured_provider", "policy_file"}:
        raise ValueError("cli_proxy requires endpoint, configured_provider and policy_file")
    if reviewer:
        raise ValueError("CLI_PROXY_OPENAI_REVIEWER_NOT_QUALIFIED: upstream identity is proxy-attested only")
    if profile.get("provider") != "openai" or not profile.get("model") or profile.get("codex_profile"):
        raise ValueError("cli_proxy requires explicit OpenAI model and does not inherit Codex profiles")
    endpoint = transport["endpoint"]
    if not isinstance(endpoint, str):
        raise ValueError("invalid proxy endpoint")
    parsed = urllib.parse.urlsplit(endpoint)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.path != "/v1" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("qualified local CLI proxy endpoint must be http://127.0.0.1:PORT/v1")
    if not isinstance(transport["configured_provider"], str) or not re.fullmatch(r"[A-Za-z0-9_-]+", transport["configured_provider"]):
        raise ValueError("invalid configured proxy provider")
    if not isinstance(transport["policy_file"], str) or not Path(transport["policy_file"]).is_absolute():
        raise ValueError("proxy policy_file must be absolute")
    return transport


def docker_json(*args):
    import subprocess
    binary = AppServerCodex._trusted_executable("docker")
    result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=15,
                            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})
    if result.returncode:
        raise RuntimeError("managed proxy Docker verification failed")
    return json.loads(result.stdout)


class ProxyPolicy:
    """Bind endpoint to the running, pinned, read-only single-credential instance."""

    def __init__(self, transport):
        self.transport = transport
        self.path = private_file(transport["policy_file"])
        self.policy = json.loads(self.path.read_text())
        if set(self.policy) != {"version", "container", "image", "endpoint", "config_file", "auth_file", "credential_file", "management_token_file"} or self.policy["version"] != 1:
            raise ValueError("invalid managed proxy policy")
        if not isinstance(self.policy["image"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", self.policy["image"]):
            raise ValueError("managed proxy image must be pinned by content digest")
        if self.policy["endpoint"] != transport["endpoint"]:
            raise ValueError("proxy endpoint differs from managed policy")
        for key in ("config_file", "auth_file", "credential_file", "management_token_file"):
            private_file(self.policy[key])
            if not Path(self.policy[key]).is_relative_to(self.path.parent):
                raise ValueError("all proxy authentication sources must stay inside the private policy directory")
        self.key = read_private_token(Path(self.policy["credential_file"]))
        self.management_key = read_private_token(Path(self.policy["management_token_file"]))
        self.identity = self.verify()

    def management(self, path):
        base = self.transport["endpoint"].removesuffix("/v1")
        request = urllib.request.Request(base+"/v0/management/"+path,
                                         headers={"Authorization": "Bearer "+self.management_key})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=5) as response:
            data = response.read(2*1024*1024+1)
        if len(data) > 2*1024*1024:
            raise ValueError("proxy management response limit exceeded")
        return json.loads(data)

    def verify(self):
        p = self.policy
        for key in ("config_file", "auth_file", "credential_file", "management_token_file"):
            private_file(p[key])
        config = json.loads(Path(p["config_file"]).read_text())
        auth = json.loads(Path(p["auth_file"]).read_text())
        # A closed schema prevents hidden YAML aliases, provider mappings,
        # payload rewrites, plugin routing and per-credential retry overrides.
        if set(config) != {"config-version", "server", "management", "access", "routing", "requests", "oauth", "upstream", "observability"}:
            raise ValueError("managed proxy config contains unsupported routing controls")
        if config["config-version"] != 8 or config["routing"] != {"strategy": "fill-first", "retry": {"request-retry": 0, "max-retry-credentials": 1, "max-retry-interval": 0}}:
            raise ValueError("managed proxy retries must be zero and credential attempts bounded to one")
        request_config = config["requests"]
        if (set(request_config) != {"proxy-url", "passthrough-headers", "streaming", "disable-image-generation"}
                or request_config["streaming"] != {"bootstrap-retries": 0, "keepalive-seconds": 0}
                or request_config["disable-image-generation"] is not True
                or request_config["passthrough-headers"] is not True):
            raise ValueError("managed proxy streaming retries/tools are not bounded")
        if config["oauth"] != {"auth-dir": "/factory-auth"} or config["upstream"] != {"codex": {"response-steering": False, "stream-bootstrap-buffering": False}}:
            raise ValueError("managed proxy must disable websocket replay and route steering")
        if config["access"] != {"api-keys": [self.key]}:
            raise ValueError("managed proxy authentication source differs")
        if auth.get("type") != "codex" or auth.get("disabled") is True or not auth.get("access_token"):
            raise ValueError("managed proxy requires one active Codex credential")
        if (set(auth) - {"type", "access_token", "refresh_token", "id_token", "account_id", "email", "expired", "last_refresh", "request_retry", "websockets"}
                or type(auth.get("request_retry")) is not int or auth["request_retry"] != 0 or auth.get("websockets") is not False):
            raise ValueError("credential aliases, route overrides and replay are forbidden")
        if any(auth.get(k) for k in ("base_url", "proxy_url", "proxy-url", "models", "prefix", "headers", "request_retry", "request-retry", "websockets")):
            raise ValueError("proxy credential contains route/retry overrides")
        if config["server"] != {"host": "", "port": 8317, "tls": {"enable": False}}:
            raise ValueError("unsupported managed proxy server config")
        if config["management"] != {"allow-remote": True, "secret-key": self.management_key, "disable-control-panel": True}:
            raise ValueError("unsupported managed proxy management config")
        if config["observability"] != {"logging": {"debug": False, "request-log": False, "logging-to-file": False}, "usage": {"usage-statistics-enabled": True, "redis-usage-queue-retention-seconds": 3600}}:
            raise ValueError("managed proxy must disable secret-bearing request logs and enable telemetry")
        container = docker_json("inspect", p["container"])[0]
        port = str(urllib.parse.urlsplit(p["endpoint"]).port)
        if (not container["State"]["Running"] or container["Image"] != p["image"]
                or container["Config"]["Cmd"] != ["/CLIProxyAPI/CLIProxyAPI", "-config", "/CLIProxyAPI/config.yaml", "-local-model"]
                or container["Config"].get("Entrypoint")
                or container["HostConfig"]["PortBindings"] != {"8317/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]}
                or not container["HostConfig"]["ReadonlyRootfs"]
                or container["HostConfig"].get("Privileged", False)
                or any(v.split("=", 1)[0] not in ("PATH", "TZ") for v in container["Config"].get("Env", []))):
            raise ValueError("proxy endpoint/runtime identity differs from pinned policy")
        mounts = {m["Destination"]: m for m in container["Mounts"] if m["Type"] == "bind"}
        expected = {"/CLIProxyAPI/config.yaml": p["config_file"], "/factory-auth": str(Path(p["auth_file"]).parent)}
        if set(mounts) != set(expected) or any(mounts[d]["Source"] != s or mounts[d]["RW"] for d,s in expected.items()):
            raise ValueError("managed proxy config and credential mounts must be pinned read-only")
        if list(Path(p["auth_file"]).parent.iterdir()) != [Path(p["auth_file"])]:
            raise ValueError("managed proxy requires exactly one credential file")
        if self.management("request-retry") != {"request-retry": 0} or self.management("max-retry-credentials") != {"max-retry-credentials": 1}:
            raise ValueError("running proxy retry policy differs from configuration")
        return {"container_id": container["Id"], "image": p["image"], "config_sha256": digest({**config, "access": {"credential": "PRESENT"}, "management": {"credential": "PRESENT"}}),
                "credential_class": "codex", "upstream_attestation": "NOT_PROVABLE",
                "retry_policy": {"request_retries": 0, "bootstrap_retries": 0, "max_credentials": 1, "websockets": False}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError("proxy redirects are forbidden")


class ProxyRelay:
    """A run-local HTTP observer; forwards once, never stores prompts or secrets.

Each Responses POST is reserved in a durable JSONL before network dispatch.
A failed/unknown request latches the entire run closed, including native retries.
Reported response models are checked on the actual SSE/JSON, not thread config.
"""

    def __init__(self, profile, transcript, timeout, token_limit=None, *, progress_driven=False):
        if progress_driven and token_limit is not None:
            raise ValueError("progress relay cannot inherit token cutoff")
        self.profile = profile
        self.policy = ProxyPolicy(validate_transport(profile))
        self.lease = (self.policy.path.parent / "factory-run.lock").open("a")
        try:
            fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lease.close()
            raise RuntimeError("managed proxy already has a Factory run; no dispatch") from None
        self.endpoint = self.policy.transport["endpoint"]
        self.nonce = secrets.token_urlsafe(32)
        self.timeout = timeout
        self.progress_driven = progress_driven
        self.deadline = time.monotonic()+timeout
        self.token_limit = token_limit
        self.token_baseline = 0
        self.records = []
        self.failed = False
        self.accepting = True
        self.lock = threading.RLock()
        self.evidence = transcript.with_suffix(".proxy.jsonl")
        self.evidence.touch(mode=0o600, exist_ok=False)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        relay = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_error(405)
            def do_POST(self):
                relay.forward(self)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}/v1"

    def start_turn(self, transcript, timeout, token_limit):
        """Rotate immutable operation evidence while retaining thread totals."""
        with self.lock:
            if self.failed:
                raise ValueError("uncertain proxy session cannot start a repair")
            if self.progress_driven and token_limit is not None:
                raise ValueError("progress repair cannot inherit token cutoff")
            if self.progress_driven:
                self.timeout = timeout
            evidence = transcript.with_suffix(".proxy.jsonl")
            evidence.touch(mode=0o600, exist_ok=False)
            self.evidence = evidence
            self.accepting = True
            self.token_baseline = tokens(self.usage()) or 0
            self.token_limit = token_limit
            self.deadline = time.monotonic() + timeout

    def persist(self, record):
        with self.evidence.open("a") as stream:
            stream.write(json.dumps(record, sort_keys=True)+"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def usage(self):
        known = [r["usage"] for r in self.records if tokens(r.get("usage")) is not None]
        if not known:
            return None
        result = {"input_tokens": sum(x["input_tokens"] for x in known), "output_tokens": sum(x["output_tokens"] for x in known),
                  "total_tokens": sum(x["input_tokens"]+x["output_tokens"] for x in known)}
        if all("cached_input_tokens" in x for x in known):
            result["cached_input_tokens"] = sum(x["cached_input_tokens"] for x in known)
        return result

    def observe(self, data, record):
        value = json.loads(data)
        response = value.get("response", value)
        if not isinstance(response, dict):
            raise ValueError("invalid proxy response")
        # Retain valid usage even when a subsequent identity check fails.
        usage = response.get("usage")
        if isinstance(usage, dict):
            partial = {k: usage[k] for k in ("input_tokens", "output_tokens")
                       if type(usage.get(k)) is int and usage[k] >= 0}
            if partial:
                record["observed_partial_usage"] = partial
            if tokens(usage) is not None and len(partial) == 2:
                record["usage"] = partial
                details = usage.get("input_tokens_details")
                cached = details.get("cached_tokens") if isinstance(details, dict) else None
                if type(cached) is int and 0 <= cached <= partial["input_tokens"]:
                    record["usage"]["cached_input_tokens"] = cached
        model = response.get("model")
        if model:
            record["reported_model"] = model
            if model != self.profile["model"]:
                raise ValueError("proxy reported a different model")
        if response.get("id"):
            record["response_id"] = response["id"]
        terminal = value.get("type")
        if terminal == "response.completed" or response.get("status") == "completed":
            record["status"] = "COMPLETE"
        if terminal in ("response.failed", "response.incomplete", "error"):
            raise ValueError("proxy generation failed or incomplete")

    def forward(self, handler):
        # Serializing makes each HTTP request's physical attempt/usage unambiguous.
        with self.lock:
            if handler.headers.get("Authorization") != "Bearer "+self.nonce:
                handler.send_error(403)
                return
            if not self.accepting:
                self.failed = True
            if self.failed or handler.path != "/v1/responses":
                handler.send_error(503)
                return
            record = None
            body = None
            sent_headers = False
            try:
                size = int(handler.headers.get("Content-Length", "0"))
                if not 0 < size <= 8*1024*1024:
                    raise ValueError("invalid request size")
                body = handler.rfile.read(size)
                request = json.loads(body)
                if request.get("model") != self.profile["model"]:
                    raise ValueError("proxy requested a different model")
                current = self.policy.verify()
                if current != self.policy.identity:
                    raise ValueError("proxy runtime policy changed")
                if not self.progress_driven and (len(self.records) >= 128 or self.token_limit and (tokens(self.usage()) or 0) - self.token_baseline >= self.token_limit):
                    raise ValueError("proxy run allowance exhausted")
                record = {"dispatch_id": self.evidence.stem, "http_request_id": str(uuid.uuid4()), "requested_model": request["model"],
                          "endpoint": self.endpoint, "status": "DISPATCHED", "usage": None,
                          "physical_attempt_limit": 1, "physical_attempt_count": "UNKNOWN", "money": "UNKNOWN"}
                self.records.append(record)
                self.persist(record)
                req = urllib.request.Request(self.endpoint+"/responses", data=body,
                      headers={"Authorization": "Bearer "+self.policy.key, "Content-Type": "application/json",
                               "Session_id": record["http_request_id"]})
                remaining = self.timeout if self.progress_driven else self.deadline-time.monotonic()
                if remaining <= 0:
                    raise ValueError("proxy run deadline exhausted")
                with self.opener.open(req, timeout=remaining) as response:
                    record["proxy_http_status"] = response.status
                    handler.send_response(response.status)
                    handler.send_header("Content-Type", response.headers.get("Content-Type", "text/event-stream"))
                    handler.send_header("Connection", "close")
                    handler.end_headers()
                    sent_headers = True
                    count = 0
                    if "text/event-stream" in response.headers.get("Content-Type", ""):
                        for line in response:
                            if not self.progress_driven and time.monotonic() >= self.deadline:
                                raise ValueError("proxy run deadline exhausted")
                            count += len(line)
                            if count > 16*1024*1024 or len(line) > 2*1024*1024:
                                raise ValueError("proxy response limit exceeded")
                            if line.startswith(b"data:") and line[5:].strip() != b"[DONE]":
                                self.observe(line[5:].strip(), record)
                            handler.wfile.write(line)
                            handler.wfile.flush()
                    else:
                        data = response.read(2*1024*1024+1)
                        if len(data) > 2*1024*1024:
                            raise ValueError("proxy response limit exceeded")
                        self.observe(data, record)
                        handler.wfile.write(data)
                if record["status"] != "COMPLETE" or record.get("reported_model") != request["model"] or not record.get("response_id") or tokens(record["usage"]) is None:
                    raise ValueError("proxy completion/model/usage unproven")
                # A completed response proves one generation in this bounded
                # policy. On failures it could be zero or one; never guess.
                record["physical_attempt_count"] = 1
                if self.policy.verify() != self.policy.identity:
                    raise ValueError("proxy policy changed during dispatch")
            except Exception as exc:
                if isinstance(exc, urllib.error.HTTPError):
                    exc.close()  # Do not let GC log upstream reason/error bodies.
                self.failed = True
                if record is None:
                    self.persist({"event": "REQUEST_NOT_DISPATCHED", "reason_code": "LOCAL_POLICY_REJECTED",
                                  "request_sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
                                  "request_bytes": len(body) if body is not None else 0})
                if record is not None:
                    record["status"] = "UNKNOWN"
                    record["physical_attempt_count"] = "UNKNOWN"
                if not sent_headers:
                    handler.send_error(502, "Explicit proxy route failed; no retry or fallback")
            finally:
                handler.close_connection = True
                if record is not None:
                    self.persist(record)

    def receipt(self):
        with self.lock:
            return {"logical_run_id": self.evidence.stem, "physical_attempts": list(self.records),
                    "physical_attempt_limit_per_http_request": 1,
                    "physical_attempt_count": sum(r["physical_attempt_count"] for r in self.records) if self.records and not self.failed and all(type(r["physical_attempt_count"]) is int for r in self.records) else "UNKNOWN",
                    "usage_complete": bool(self.records) and not self.failed and all(r["status"] == "COMPLETE" and len(r.get("proxy_telemetry", [])) == 1 for r in self.records),
                    "upstream_provider_identity": "NOT_PROVABLE", "upstream_model_identity": "NOT_PROVABLE",
                    "money": "UNKNOWN"}

    def collect_telemetry(self):
        """Consume only the dedicated pool's queue, persisting an allowlist.

        Raw queue entries include API keys, account details and error bodies;
        those never leave this method. A unique per-HTTP session UUID links a
        dispatch to the proxy's request/execution IDs and its model/usage claims.
        A missing entry remains unknown, not evidence of zero physical attempts.
        """
        with self.lock:
            self.accepting = False  # Only the next authorized turn can reopen dispatch.
            try:
                rows = self.policy.management("usage-queue?count=256")
                if not isinstance(rows, list):
                    raise ValueError("proxy usage telemetry is unavailable")
                fields = ("provider", "executor_type", "model", "response_model", "request_id", "execution_id", "trace_id", "session_id", "auth_type", "failed")
                for row in rows:
                    if not isinstance(row, dict):
                        self.failed = True
                        continue
                    matched = next((r for r in self.records if r["http_request_id"] == row.get("session_id")), None)
                    if matched is None:
                        # A dedicated route must have no unattributed requests.
                        self.failed = True
                        continue
                    safe = {key: row[key] for key in fields if key in row and isinstance(row[key], (str, bool))}
                    raw_tokens = row.get("tokens")
                    safe["usage"] = {key: raw_tokens.get(key) for key in ("input_tokens", "output_tokens", "total_tokens")
                                     if isinstance(raw_tokens, dict) and type(raw_tokens.get(key)) is int and raw_tokens[key] >= 0}
                    matched.setdefault("proxy_telemetry", []).append(safe)
                    valid = (len(matched["proxy_telemetry"]) == 1 and safe.get("provider") == "codex"
                             and safe.get("executor_type") == "CodexExecutor" and safe.get("failed") is False
                             and safe.get("model") == matched["requested_model"] == safe.get("response_model")
                             and bool(safe.get("request_id")) and bool(safe.get("execution_id"))
                             and tokens(safe["usage"]) is not None and matched.get("usage") is not None
                             and all(safe["usage"].get(k) == matched["usage"].get(k) for k in ("input_tokens", "output_tokens")))
                    if not valid:
                        self.failed = True
                        matched["status"] = "UNKNOWN"
                        matched["physical_attempt_count"] = "UNKNOWN"
                    self.persist(matched)
                if any(len(r.get("proxy_telemetry", [])) != 1 for r in self.records):
                    self.failed = True
            except Exception:
                self.failed = True
                raise ValueError("proxy telemetry unproven; no retry or fallback") from None

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.lease.close()

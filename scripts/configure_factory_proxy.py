#!/usr/bin/env python3
"""Create an explicit Factory-only CLIProxyAPI route, without inference.

Copies one existing active Codex auth into a private, read-only credential pool.
Does not change the user's interactive proxy, Codex config or Factory missions.
"""
import argparse
import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from harness.factory_proxy import (
    LEGACY_PROXY_IMAGE, PROXY_V8_0_77_IMAGES, SUPPORTED_PROXY_RELEASES, ProxyPolicy,
    private_file, verify_snapshot_expiry,
)


def managed_config(key, management_key, network_proxy, image=LEGACY_PROXY_IMAGE):
    config = {"config-version": 8,
            "server": {"host": "", "port": 8317, "tls": {"enable": False}},
            "management": {"allow-remote": True, "secret-key": management_key, "disable-control-panel": True},
            "access": {"api-keys": [key]},
            "routing": {"strategy": "fill-first", "retry": {"request-retry": 0, "max-retry-credentials": 1, "max-retry-interval": 0}},
            "requests": {"proxy-url": network_proxy, "passthrough-headers": True, "streaming": {"bootstrap-retries": 0, "keepalive-seconds": 0}, "disable-image-generation": True},
            "oauth": {"auth-dir": "/factory-auth"},
            "upstream": {"codex": {"response-steering": False, "stream-bootstrap-buffering": False}},
            "observability": {"logging": {"debug": False, "request-log": False, "logging-to-file": False}, "usage": {"usage-statistics-enabled": True, "redis-usage-queue-retention-seconds": 3600}}}
    if image in PROXY_V8_0_77_IMAGES:
        config["multimedia"] = {
            "disable-image-generation": config["requests"].pop("disable-image-generation"),
        }
        config["observability"]["logs"] = config["observability"].pop("logging")
    return config


def managed_credential(auth, image):
    fields = {"type", "access_token", "id_token", "account_id", "email", "expired", "last_refresh"}
    if image not in PROXY_V8_0_77_IMAGES:
        fields.add("refresh_token")
    selected = {key: auth[key] for key in fields if key in auth}
    selected.update(request_retry=0, websockets=False)
    if image in PROXY_V8_0_77_IMAGES:
        verify_snapshot_expiry(selected)
    return selected


def verify_release(image, banner):
    release = SUPPORTED_PROXY_RELEASES.get(image)
    match = re.search(r"(?m)^CLIProxyAPI Version: ([^,]+), Commit: ([0-9a-f]{7,40}),", banner)
    if not release or not match or match[1] != release[0] or not release[1].startswith(match[2]):
        raise ValueError("CLIProxyAPI version, commit and image must match a supported release")


def write(path, value):
    with path.open("x") as stream:
        stream.write(value)
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-container", default="cli-proxy-api")
    parser.add_argument("--auth-file", type=Path, required=True)
    parser.add_argument("--name", default="cmh-factory-cli-proxy")
    parser.add_argument("--port", type=int, default=18317)
    parser.add_argument("--network", default="cliproxyapi_default")
    parser.add_argument("--network-proxy", default="http://172.21.0.1:7897")
    args = parser.parse_args()
    auth = json.loads(private_file(args.auth_file).read_text())
    if auth.get("type") != "codex" or auth.get("disabled") is True or not auth.get("access_token"):
        parser.error("choose one existing enabled Codex auth file")
    source = json.loads(subprocess.check_output(["docker", "inspect", args.source_container]))[0]
    version = subprocess.run(["docker", "exec", args.source_container, "/CLIProxyAPI/CLIProxyAPI", "--help"], capture_output=True, text=True, timeout=10)
    try:
        verify_release(source["Image"], version.stdout + version.stderr)
        selected = managed_credential(auth, source["Image"])
    except ValueError as exc:
        parser.error(str(exc))
    root = args.directory.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    auth_dir = root / "auth"
    auth_dir.mkdir(mode=0o700)
    key, management_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    config_path = root / "config.json"
    auth_path = auth_dir / "codex.json"
    key_path = root / "proxy-key"
    management_path = root / "management-key"
    write(config_path, json.dumps(managed_config(key, management_key, args.network_proxy, source["Image"]), indent=2)+"\n")
    write(auth_path, json.dumps(selected)+"\n")
    write(key_path, key+"\n")
    write(management_path, management_key+"\n")
    endpoint = f"http://127.0.0.1:{args.port}/v1"
    policy = {"version": 1, "container": args.name, "image": source["Image"], "endpoint": endpoint,
              "config_file": str(config_path), "auth_file": str(auth_path),
              "credential_file": str(key_path), "management_token_file": str(management_path)}
    write(root / "policy.json", json.dumps(policy, indent=2)+"\n")
    # No credential in args or env; secret files are never copied to artifacts.
    subprocess.run(["docker", "run", "-d", "--name", args.name, "--read-only", "--network", args.network,
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "-p", f"127.0.0.1:{args.port}:8317",
                    "--mount", f"type=bind,src={config_path},dst=/CLIProxyAPI/config.yaml,readonly",
                    "--mount", f"type=bind,src={auth_dir},dst=/factory-auth,readonly",
                    source["Image"], "/CLIProxyAPI/CLIProxyAPI", "-config", "/CLIProxyAPI/config.yaml", "-local-model"], check=True, capture_output=True)
    transport = {"type": "cli_proxy", "endpoint": endpoint, "configured_provider": "cli_proxy_api", "policy_file": str(root / "policy.json")}
    for attempt in range(20):
        try:
            result = ProxyPolicy(transport)
            break
        except (OSError, RuntimeError, ValueError):
            if attempt == 19:
                raise RuntimeError("dedicated proxy did not become ready; no inference dispatched") from None
            time.sleep(.25)
    print(json.dumps({"transport": transport, "runtime": result.identity, "model_inference_calls": 0,
                      "note": "Developer/planner only; proxy OpenAI reviewer is not qualified"}, indent=2))


if __name__ == "__main__":
    main()

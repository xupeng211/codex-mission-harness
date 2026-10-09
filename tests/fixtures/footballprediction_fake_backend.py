"""OFFLINE ONLY: real project wrappers/validators with synthetic backend identity.

Invoked only by the integration test's launcher interception. No credentials,
network or actual model invocation; generated receipts are temporary test data.
"""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

snapshot, mode, binary, *arguments = sys.argv[1:]
sys.path.insert(0, snapshot)


def record_call():
    directory = Path(arguments[arguments.index("--evidence-dir") + 1])
    with (directory / "offline-fake-backend-calls.jsonl").open("a") as stream:
        stream.write(json.dumps({"fixture": True, "backend": mode}) + "\n")


if mode == "deepseek":
    from scripts.devops import claude_deepseek_independent_review as runner
    from scripts.devops.independent_review_protocol import canonical_json

    def fake_deepseek(*, prompt, cwd):
        record_call()
        result = {"protocol_version": "INDEPENDENT_REVIEW_PROTOCOL_V1",
                  "review_result": "PASS", "findings": []}
        command = ("/offline-fixture/claude", "--bare", "--restricted", "--print",
                   "--model", "deepseek-flash", "--settings", "/offline-fixture/settings.json",
                   "--strict-mcp-config", "--tools", "", "--disallowed-tools",
                   "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch",
                   "--output-format", "json", "--json-schema", '{"type":"object"}', prompt)
        raw = canonical_json({"is_error": False, "session_id": "offline-fixture-session",
                              "structured_output": result,
                              "modelUsage": {"deepseek-flash": {"canonicalModel": "deepseek-flash"}}})
        return raw, result, SimpleNamespace(
            command=command, resolved_model="deepseek-flash", cli_version="2.1.276",
            binary_sha256="d" * 64, settings_sha256="e" * 64,
            endpoint="https://api.deepseek.com/anthropic", session_id="offline-fixture-session")

    runner.backend.run = fake_deepseek
else:
    from scripts.devops import codex_independent_review as runner
    from scripts.devops import codex_review_classification as classification
    from scripts.devops.codex_review_contract import review_challenge
    from scripts.devops.codex_reviewer_isolation import ISOLATION_POLICY_VERSION

    # The official auth probe is replaced, never run or claimed as verified.
    # The original receipt classifier still checks the fixture's exact binary.
    for module in (runner, classification):
        module.canonical_codex_binary = lambda: Path(binary)
        module.canonical_reviewer_environment = lambda **_: {"PATH": "/usr/bin:/bin"}

    runner.canonical_reviewer_preflight = lambda **_: {
        "policy": ISOLATION_POLICY_VERSION, "canonical_codex_home_external": True,
        "canonical_codex_home_owner_only": True, "authentication_mode": "official_chatgpt_stored_state",
        "builder_auth_override_inherited": False, "custom_model_provider_inherited": False,
        "cliproxyapi_routing_inherited": False, "generic_network_proxy_preserved": False,
        "user_codex_config_ignored": True, "pinned_model_active": True, "pinned_reasoning_active": True}
    original_run = subprocess.run

    def fake_codex(command, **kwargs):
        if str(command[0]) != binary or "--version" in command:
            return original_run(command, **kwargs)
        record_call()
        args = runner.build_parser().parse_args(arguments)
        scope_hash = runner.sha256_file(Path(args.mission_scope_file))
        document = {"result": "PASS", "findings": [], "review_challenge": review_challenge(
            mission_id=args.mission_id, base_sha=args.base_sha, head_sha=args.head_sha,
            mission_scope_sha256=scope_hash)}
        final = json.dumps(document)
        Path(command[command.index("--output-last-message") + 1]).write_text(final)
        events = [{"type": "thread.started", "thread_id": "offline-fixture-thread-1234"},
                  {"type": "item.completed", "item": {"type": "agent_message", "text": final}},
                  {"type": "turn.completed"}]
        return subprocess.CompletedProcess(command, 0,
            ("\n".join(json.dumps(event) for event in events) + "\n").encode(), b"")

    subprocess.run = fake_codex

raise SystemExit(runner.main(arguments))

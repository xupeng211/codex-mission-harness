# Explicit CLI proxy transport

Factory supports `official` and `cli_proxy` as separate, explicit transports for
Codex planning/development. Existing profiles without `transport` remain official;
there is no automatic inheritance of the user's selected Codex provider and no
fallback between endpoints. For the complete lane configuration and separate official
reviewer authentication, see [HYBRID_FACTORY.md](HYBRID_FACTORY.md). DeepSeek review stays directly on
`https://api.deepseek.com/chat/completions`.

CLI proxy OpenAI review is **not qualified**. A proxy's model directory, response
model and correlated usage queue are proxy attestations, not an independent proof
of the actual upstream provider/backend. A reviewer profile selecting `cli_proxy`
is rejected before dispatch. Thus a working developer route does not make a full
dual-provider Factory delivery READY; the official OpenAI reviewer must still work.
The historical official-route receipts remain intact.

## Configure a bounded dedicated instance

The supported policy is a local Docker CLIProxyAPI instance with one active Codex
OAuth credential. The provisioner checks the version banner against the commit
paired with the local Docker image ID. The runtime accepts only these image IDs:

| Release | Commit | Docker image ID |
| --- | --- | --- |
| v8.0.15 | `a4acc9f752bd46571f737a10c04bf413656ab06b` | `sha256:ebc2ffc189cf241ff589cd9237c63ca9feba3c9b87fe6213ab9a0b642df132ae` |
| v8.0.77 (linux/amd64) | `a5e8f69e56309e1ef6d6872e667da81fdfbce2ce` | `sha256:61451a1fce07e70fb86bc52939b3b99bcb0d4c98a94483bb880017d2937f5e1e` |

The published linux/amd64 manifest for v8.0.77 is
`docker.io/eceasy/cli-proxy-api@sha256:61451a1fce07e70fb86bc52939b3b99bcb0d4c98a94483bb880017d2937f5e1e`.
For this image the generated config uses `multimedia.disable-image-generation`
and `observability.logs`. Existing v8.0.15 policies use their original layout.

The original interactive instance can keep its configuration. A Factory-only copy
uses zero credential/stream bootstrap retries, a single credential per request,
disabled WebSockets/model aliases/steering, read-only configuration and credential
mounts, and a loopback-only published port. Its read-only credential snapshot must
be reprovisioned when expired; failure never rotates to another account.

Use an owner-controlled mode-0600 input auth file in a private directory. If the
existing proxy auth directory is writable by other users, first make a private
copy; do not change the interactive proxy's credential or put the copy in Git.

```bash
python3 scripts/configure_factory_proxy.py \
  --source-container cli-proxy-api \
  --auth-file /absolute/private-directory/existing-codex-auth.json \
  --directory /absolute/private-directory/factory-proxy \
  --name cmh-factory-cli-proxy --port 18317 \
  --network cliproxyapi_default --network-proxy http://172.21.0.1:7897
```

This performs no model inference. It creates private key files and a safe
`policy.json`, and reports only configuration/runtime identity. Do not upload the
configuration/key/auth files as CI artifacts. The policy directory must remain
outside the candidate repository. No secret is passed through Docker/Codex argv.

The generic Factory profile extension is:

```json
{
  "developer": {
    "provider": "openai",
    "model": "gpt-6.1-sol",
    "effort": "high",
    "transport": {
      "type": "cli_proxy",
      "endpoint": "http://127.0.0.1:18317/v1",
      "configured_provider": "cli_proxy_api",
      "policy_file": "/absolute/private-directory/factory-proxy/policy.json"
    }
  },
  "reviewer": {
    "provider": "openai",
    "transport": {"type": "official"}
  },
  "second_reviewer": {
    "provider": "deepseek",
    "model": "deepseek-flash",
    "token_file": "/absolute/private-directory/deepseek-token"
  }
}
```

Use a **new** Factory configuration, mission and state directory for qualification.
Do not change/resume/refund a historical UNKNOWN mission to switch routes.
`harness setup` also accepts `--transport cli_proxy --model ... --proxy-endpoint ...
--proxy-policy-file ...`; it keeps the reviewer official. Model and endpoint are
mandatory explicit choices. Only `http://127.0.0.1:PORT/v1` is currently supported.

## Evidence, isolation and accounting

The route identity records the configured provider, real proxy endpoint, requested
model, credential source path, pinned container/image/config identity and retry
policy. The profile identity additionally binds Codex version, launcher path/hash,
adapter hashes and reasoning effort. A different route/runtime creates a different
qualification/evidence identity. Completed response receipts carry the actual
reported model and response ID; mismatches fail closed.

A small run-local observer forwards each Responses HTTP request **once**. Codex
uses a fresh private home containing an observer capability, while the real proxy
key and OAuth credential stay outside its process and delegated shell environment.
Secrets are never in command arguments or receipts. Filesystem rules deny the
original Codex home, observer home and private policy directory; the delegated
network is disabled. Explicit environment allowlists remain in effect.

Each HTTP dispatch is durably reserved before forwarding in `.proxy.jsonl`, linked
to its logical Factory operation. Terminal SSE/JSON is checked for response ID,
exact model and valid input/output usage. Usage is aggregated over HTTP requests,
including repeated input/cached input; a turn count is never called a physical
request count. Under the pinned no-retry/single-credential policy, a completed
request accounts for one generation attempt; an uncertain request is recorded as
UNKNOWN with an attempt limit of one, never guessed as zero. Non-generating OAuth
refresh and management requests are not generation attempts.

The dedicated usage queue links the observer's per-HTTP session UUID to proxy
request/execution IDs, provider/executor class, requested/reported models and token
usage. Only an allowlist is persisted: no API key, account/email, token hash,
cookie, header collection or error body. Multiple execution records for a single
dispatch fail closed. Queue consumption is serialized by an exclusive Factory-run
lease; concurrent use of the same dedicated route is rejected.

Failures latch the observer closed for the entire run. Native retry attempts are
rejected locally; Factory UNKNOWN operations remain unreplayed even after the
proxy recovers. Observed partial usage remains recorded, with the full UNKNOWN run
reservation retained. No reliable money telemetry is available: `money=UNKNOWN`.
Local Docker policy and effective retry settings are checked before each forward
and after completion. Unsupported or changed policies stop without fallback.

## Real qualification

This explicit command spends model tokens in an isolated fixture and creates a new
ledger. Never point it at a historical state directory:

```bash
python3 scripts/qualify_factory_proxy.py \
  --output /absolute/new-qualification-directory \
  --policy-file /absolute/private-directory/factory-proxy/policy.json \
  --endpoint http://127.0.0.1:18317/v1 --model gpt-6.1-sol \
  --deepseek-token-file /absolute/private-directory/deepseek-token
```

It runs real planning/development, sandboxed tests and direct DeepSeek review. It
does not run or pretend to pass a proxy OpenAI reviewer, and does not claim full
Factory READY. Unknown/truncated reviews remain in their new ledger without
automatic retries. Native offline tests cover official transport, proxy selection,
credential isolation and no-fallback; HTTP contract tests cover bounded attempts,
identity mismatches, partial usage, unknown reservations and immutable receipts.

## Task-level model pool

[MODEL_ROUTING.md](MODEL_ROUTING.md) describes the opt-in deterministic developer
pool, offline preview, immutable task/model/route binding and conditional token
cost observations. Pool entries still pass every dedicated-instance check above;
aliases, hidden retries and multi-credential fallback are not newly authorized.
Completion also requires exactly one matching queue execution per HTTP dispatch,
with matching provider/executor/model/token claims and no unattributed queue rows.
Missing telemetry is UNKNOWN. Same-thread repair rotates immutable relay evidence
and applies its existing incremental token authority without selecting a new model.

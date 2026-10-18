# Hybrid Factory: proxy development, independent official review

The production lane configuration is explicit:

| Lane | Route | Authentication | Identity evidence |
| --- | --- | --- | --- |
| planner/developer/rework | `cli_proxy`, loopback Factory-only instance | Controller-held proxy key; private observer capability | Responses model/ID, per-HTTP attempts and usage, pinned Docker policy |
| OpenAI reviewer | `official`, native Codex official authentication | Separate private `CODEX_HOME`, ChatGPT OAuth | Trusted native runtime, official provider selection, completed structured turn, thread/turn IDs, model/reroute events and usage |
| DeepSeek reviewer | `direct`, `https://api.deepseek.com/chat/completions` | Private DeepSeek token file | HTTPS endpoint, returned model/response ID, complete structured result and usage |

No lane falls back to another route. CLI proxy is not an OpenAI reviewer. Native
OpenAI's reported model evidence is the App Server's selected thread model and
reroute events, not an invented raw HTTP response model or response ID. The exact
native runtime and completed turn are included; unavailable HTTP IDs are not guessed.

## Separate official authentication

Keep daily Codex's `/home/xupeng/.codex` proxy configuration unchanged. Official
review can use `/home/xupeng/.codex-harness-official`, owned by the user with mode
0700 and mode-0600 authentication files. This directory has only official model
configuration, no custom gateway/provider or proxy bearer token. An existing
valid official Codex OAuth login cache can be safely copied by the local maintainer
into the separate home; authentication still requires a real official inference.
If a new sign-in is needed, the user completes it once:

```bash
env CODEX_HOME=/home/xupeng/.codex-harness-official codex login
```

Never paste authentication JSON, tokens or credentials into a chat, argv, report,
Git or CI artifacts. Refresh/login updates this home only. A login status message
is not qualification. See [official Codex authentication documentation](https://developers.openai.com/codex/auth/).

## Configure a new project/state

Provision the bounded Factory-only proxy as described in
[CLI_PROXY_TRANSPORT.md](CLI_PROXY_TRANSPORT.md), then configure a new file:

```bash
harness setup --repository /absolute/project \
  --transport cli_proxy --model gpt-6.1-sol \
  --proxy-endpoint http://127.0.0.1:18317/v1 \
  --proxy-policy-file /absolute/private-factory-proxy/policy.json \
  --reviewer-codex-home /home/xupeng/.codex-harness-official \
  --deepseek-token-file /absolute/private-deepseek-token \
  --deepseek-max-output-tokens 16384 \
  --config /absolute/new-hybrid-config.json
```

Select that configuration and a **new state directory** for new tasks. Do not
replace/resume a historical UNKNOWN mission to change routes. The setup override
changes only the official reviewer home; the proxy developer retains its ephemeral
home. `second_reviewer.transport={"type":"direct"}` is explicit and accepts no
endpoint override. Legacy missing transport remains the existing direct route.

DeepSeek thinking is enabled by default. The earlier 4096 completion allowance
was entirely consumed by reasoning, leaving a length-truncated result. New setup
profiles allocate 16384 while retaining the rubric, reasoning mode, complete
repository context, findings validation and token admission. Existing files are
never migrated/rewritten. A truncated result remains UNKNOWN with its observed
usage/reservation; increasing a new profile's allowance never replays that request.
See [DeepSeek thinking controls](https://api-docs.deepseek.com/guides/thinking_mode).

## Real acceptance and recovery

`scripts/factory_acceptance.py --output NEW_DIRECTORY --config HYBRID_CONFIG
--mission-id NEW_ID` runs the real production adapters. It injects a disclosed,
safe length-37 average defect after a real implementation without changing model
output/tests. Both reviewers independently see the exact target; their genuine
findings trigger proxy rework, new tests/CI and fresh official/direct rereviews.
Only an exact-target successful delivery is READY. Hosted CI can use the existing
private acceptance repository with its test-only read-only workflows.

Every paid dispatch is reserved in its new ledger. Unknown or partial results
remain charged, money is UNKNOWN without reliable telemetry, and no uncertain
request is replayed. Restarting a delivered task checks exact source/evidence
without dispatching again. Changing just the official reviewer home/model refreshes
that lane's evidence; developer and DeepSeek historical receipts remain intact.
An official authentication failure stops delivery instead of using the proxy.
Merge and release always remain explicit human decisions.

## Optional task model routing

The developer lane can opt into a small operator-declared CLIProxyAPI model pool.
See [MODEL_ROUTING.md](MODEL_ROUTING.md) and
[factory.routing.example.json](../config/factory.routing.example.json). Explicit
mission attributes select capability before price; missing attributes select
conservatively. Models/routes are bound before dispatch and remain fixed during
QA repair. Official reviewer and direct DeepSeek review profiles, local-candidate
authorization, Controller QA and publication boundaries continue to apply.
The sample has no enabled or verified actual models and makes no pricing claim.

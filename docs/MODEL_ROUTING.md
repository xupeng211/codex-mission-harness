# Task model routing MVP

Routing is opt-in through the operator Factory configuration's `model_routing`
pool. It selects the developer profile before planning/implementation starts;
reviewer profiles, official Codex App Server, Controller QA, Git isolation and
local delivery boundaries remain in place. There is no difficulty-classifier
model call, discovery probe, automatic qualification or automatic budget increase.
The existing `model_registry.py` is the separate reviewer role allowlist and is
not used as a developer capability or price database.

## Configuration and task attributes

Copy [factory.routing.example.json](../config/factory.routing.example.json) into
an owner-controlled configuration outside the candidate repository. Its model
names are placeholders; all entries are unavailable and excluded from automatic
routing. Replace names, capability/effort/category declarations and transport
policy paths with operator-verified information before enabling entries. These
metadata declarations do **not** prove account access, model quality or balance.
No actual local model or price is asserted by this example.

Each entry has a unique `id`, exact wire `model`, `route_id`, capability `tier`,
`efforts`, `categories`, declared `available`, automatic eligibility `auto`,
`protocol` (`codex_responses`), strict `transport`, and `price`. Multiple models
may share a dedicated route. A route id cannot name conflicting transports.
Pool changes are part of immutable mission policy, including availability/prices;
use a new mission/state for changes. Unselected routes are not contacted.

An optional mission v2 field selects explicit task properties:

```json
"model_routing": {
  "category": "bugfix",
  "complexity": "low",
  "risk": "low"
}
```

Categories: `general`, `docs`, `tests`, `bugfix`, `feature`, `refactor`, `security`,
`migration`. Complexity: `low`, `normal`, `complex`. Risk: `low`, `normal`, `high`.
The Controller/operator supplies these properties; generated plans cannot change
them. The router deliberately does not infer risk from natural-language text.
An inaccurate low-risk declaration can select an unsuitable model: independent
QA remains essential and savings/quality improvements require later experiments.

Selection rules, in order:

1. Complex tasks, high risk, security or migration require `high` capability.
2. Any missing category/complexity/risk conservatively requires `high`.
3. Explicit low complexity **and** low risk qualify for `economy`.
4. Other complete descriptions require `balanced`.

Optional `model` selects an exact **pool entry id**, `tier` requests a minimum
capability, and `effort` specifies reasoning effort. Neither manual override can
lower required task capability. Default efforts are low/medium/high for the
requested tier. A model must support that effort and exact task category and be
available; automatic choices additionally require `auto=true`. No match blocks
before dispatch; there is no official/proxy fallback.

Within qualifying entries the router first picks the lowest sufficient capability,
then entries with trusted configured prices, then the lowest reference cost for
100k uncached input + 10k output tokens, then lexical entry id. Unknown-price ties
are stable by id. The reference workload is a reproducible heuristic, not a task
cost forecast. Pool order does not affect which entry is selected.

Preview without reading credentials, contacting services or performing inference:

```bash
PYTHONPATH=src python3 -m harness.factory_routing \
  --config /absolute/operator-config.json --mission /absolute/new-mission.json
```

Preview returns the profile, selection reason, pool hash, price basis and
`route_access=NOT_VERIFIED`. It does not create or grant execution authority.
The disabled example intentionally fails selection until configured.
`harness submit` also accepts `--task-category`, `--task-complexity`, `--task-risk`,
`--pool-model`, `--model-tier`, `--model-effort`. Complete local-candidate missions
continue through `harness factory-run mission.json --config ...`; their existing
explicit authorization must bind `Factory.developer_binding(spec)[1]` as
`executor_identity`, along with the existing exact scope, test and budget fields.
Computing the live binding performs read-only local/runtime policy checks, not
inference. The offline preview alone cannot supply this runtime authorization.

## Supported and blocked integration routes

The model pool is a Harness selection layer over existing
[bounded CLIProxyAPI routes](CLI_PROXY_TRANSPORT.md), not permission to forward
into any ordinary provider pool. Only the pinned, dedicated single-Codex-credential,
no-retry, no-steering, no-alias Responses policy is accepted. Models can share
such an instance; different credentials require separate dedicated policy/endpoint
entries. This MVP does not add an arbitrary Claude/Gemini translator or claim that
a catalog entry can execute Codex tool/schema contracts.

The daily interactive CLIProxyAPI instance is not reconfigured. Read-only local
inspection on 2026-10-18 found retry settings of 3, unrestricted credential retry
count (0), and enabled quota project switching in its non-sensitive settings.
The local source's OAuth alias implementation explicitly maps aliases back to
upstream names; its static Codex catalog is a declaration, not availability or
billing proof. These findings explain why ordinary aliases/multi-credential
fallback pools remain blocked. No management or inference request was made to
that daily instance and no credential contents were inspected for this mission.

Selection and full runtime identity are persisted at submission and compared on
resume. Before a routed dispatch the runtime verifies the authorized route again,
then checks the newly created relay's pinned identity before any turn is sent.
The relay checks policy before and after each HTTP forward. Wire and correlated
queue requested/reported models, executor/provider and token counts must agree;
missing, duplicate, failed, mismatching or unattributed queue entries prevent
settlement. A dirty/stale dedicated queue therefore yields UNKNOWN; do not reuse
historical UNKNOWN state, consume it as zero, or silently clean it to claim PASS.

The relay closes dispatch between completed turns; only an authorized next turn
reopens it. Same-thread QA repair uses the same selected profile and route. The existing
session binding rejects a changed model/profile/workspace. Per-turn relay logs
rotate and reused-process stderr is snapshotted to preserve immutable first-turn evidence, deadlines refresh within the
mission wall authority, token observation uses incremental repair usage, and
native App Server snapshots stay separate from cumulative proxy wire snapshots.
Escalating models requires a new task/authorization, not an in-thread switch.

## Cost and evidence

`MODEL_ROUTING` in JSON delivery/status contains the task tier/reason, pool hash,
requested model/route/effort, actual wire-reported models, per-operation usage,
completeness, elapsed seconds, QA results and repair count. Raw receipts retain
HTTP dispatch/execution linkage, partial observed usage and physical attempt
uncertainty. Existing accounting retains full UNKNOWN reservations in addition to
observed partial tokens. Cached input is recorded only when valid wire telemetry
reports it; absent cache telemetry remains unknown, not zero.

Use `price: "UNKNOWN"` unless an operator has verified a non-secret price contract.
A known price object contains `currency: "USD"`, decimal-string
`input_per_million`, `output_per_million`, `cached_input_per_million`, `source`,
ISO `as_of`, and `basis: "operator_verified"`. The operator must assess price
freshness and account applicability. There is no scraped/invented rate or balance.
Only complete usage with known cache tokens produces a conditional requested-model
estimate: uncached input × input rate + cached input × cache rate + output × output
rate, divided by one million. All other estimates are UNKNOWN. Even a numeric
estimate has `actual_bill=UNKNOWN` and `upstream_model_identity=NOT_PROVABLE`.
Proxy self-report is never independent upstream proof. Monetary spend caps and
absolute physical token ceilings are not promised; existing authorized resource
admission, observation stops, cancellation and UNKNOWN protections remain active.
Proxy OpenAI review remains unqualified; official/direct independent review lanes
are unchanged. No secret values, OAuth data, account identities or request headers
are added to the pool, routing evidence or price contract.

## Verification boundary

Offline tests use synthetic model names/prices, mocks, real temporary Git clones,
local tests and loopback-only simulated proxy servers. Native Codex protocol tests
exercise configuration/thread setup without starting real model turns.
`OFFLINE_ROUTING_VERIFIED=YES` describes these checks only.
`REAL_PROXY_MODEL_DISPATCH_VERIFIED=NO` for this mission.

A future separately authorized minimum experiment would use a fresh dedicated
instance snapshot, ledger and tiny fixture, one operator-declared model and a
bounded initial turn (optional separately budgeted same-model repair). Compare
App Server, wire, queue, UNKNOWN reservation, immutable QA/patch and external bill
artifacts. A single-model test does not establish whole-pool quality or savings,
and proxy identity still needs independent evidence. No such experiment is
requested or performed by this implementation.

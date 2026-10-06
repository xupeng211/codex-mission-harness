# Reviewer resource gate

The original Mission request ledger is the only logical-call counter. The gate
checks its historical prefix against the approved call/wall authorization and
appends a `STARTED` record before a model subprocess. Settlement changes that
same record to `RETURNED` or `FAILED`. An interrupted `STARTED` request blocks
all new requests until it is reconciled; it is never counted as free.

The token/cost approval is a separate private, HMAC-protected JSON artifact.
It must bind the original Mission ID, start time, ledger path and historical
ledger hash, the call/wall authorization SHA256, provider and exact model, and
an authorization version and human approval source. The gate requires both
`token_authorization` and `cost_authorization` to be `APPROVED`. Ordinary model
configuration cannot raise the call or wall limits. An approval for one
provider or model cannot spend another provider's reserve.
DeepSeek also requires the signed authorization to declare a verified billing
route and bind the price source and independent route evidence by absolute
path and SHA256. The earlier authorization has no route evidence and continues
to deny DeepSeek launches. Public API prices alone do not prove which account
or channel was charged.

Set `CMH_RESOURCE_AUTHORIZATION`, `CMH_RESOURCE_AUTH_SHA256`,
`CMH_RESOURCE_GATE_KEY_FILE`, `CMH_RESOURCE_LEDGER`, and
`CMH_RESOURCE_MISSION_ID` from the trusted controller. The controller must also
provide `CMH_RESOURCE_FREEZE` and `CMH_RESOURCE_FREEZE_SHA256` for a signed
snapshot of the settled request prefix. Removing or changing a frozen request
cannot restore capacity. Review and
qualification runners set the run ID; stage invocations set the stage ID.
Missing, altered or pending context denies the request before `Popen`.
If the signed numeric start and the original UTC `started_at` text disagree,
the wall gate uses the earlier instant. The historical Mission records differ
by 63.599698 seconds; this conservative check preserves both original values.
OpenAI Codex, DeepSeek Reviewer V2 and both qualification paths call this
gate. A nested Codex call inside one qualification case shares that case's
reservation, so it adds only one logical request.

Each call debits its full approved input, output, reasoning, cache and cost
reservation before launch. The debit remains after success, failure or
missing usage. Reported usage and CLI USD metadata are stored separately;
they are not confirmed bills. Claude CLI reports non-cached input, cache read,
cache creation and output as separate counters aggregated over a CLI session.
Thinking tokens are part of output. DeepSeek's signed official-price estimate
charges non-cached input and cache creation at the cache-miss rate, cache read
at the cache-hit rate, and output once. The CLI's distinct first-party cost
estimate is also compared with the per-request USD reservation; an overage in
either estimate blocks later calls without being labelled a confirmed bill.
Missing or inconsistent DeepSeek usage blocks later calls. Resume reads an already committed review stage
without invoking the model, so it makes no new reservation.

**Limit of this contract:** The existing Codex CLI does not expose complete
input, output and hidden reasoning token usage, and neither current CLI path
proves a provider-enforced per-call Token cap. Fixed reservations therefore
provide a user-approved conservative *accounting* bound across calls, not a
guarantee that one physical call cannot exceed its reserve. The user must
explicitly approve this UNKNOWN-usage policy or require a metered/capped
transport before live review. A single observed overage is retained and
blocks subsequent calls; it cannot be retroactively undone.

The separate Token and cost authorization must be explicitly approved and
signed before live review begins.

## Official daily billing recovery (dormant until separately approved)

The 2026-10-02 DeepSeek export reports a paid `deepseek-flash`/`harness`
**day-level** CNY total and a unit price for each token category. It has no
provider request IDs or per-request charge. Requests 255 and 256 therefore
remain `ESTIMATED_ONLY`/`UNRESOLVED`; the original rows and full reservations
are immutable. The Claude CLI's `costBasis=unknown` value is retained as an
unbilled estimate, not silently recast as an invoice.

For a future, explicitly approved recovery, the signed resource authorization
must bind the official export by SHA256, the verified route and price evidence,
and a private HMAC-signed disposition for each historical CLI fallback overage.
The disposition binds the frozen prefix, exact request number and row SHA256,
the original CLI session artifact and its cache split by SHA256, and an
independently recomputed official-price estimate within the old reservation.
It retains the original overage, records `confirmed_billed_cost=UNKNOWN`, and
cannot refund any reservation. Only the specified immutable rows may cease
blocking later launches. This check is mission-wide, including OpenAI calls.
Request 255's old estimate used the superseded cache mapping (54,110 versus
57,220 recomputed micro-USD); request 256 has no old official estimate. The
signed disposition must state those facts without rewriting either row.
An unlisted overage, missing or changed evidence, or unapproved recovery still
blocks before a subprocess starts.

If that later authorization also selects
`VERIFIED_OFFICIAL_PRICE_WITH_DISCLOSED_CLI_FALLBACK`, a new DeepSeek request
stores the high CLI fallback estimate as an observed discrepancy. The signed
official USD price estimate remains the cost budget comparison. Missing or
inconsistent usage, a non-`unknown` CLI cost basis, or an official estimate
above the authorized per-call reserve fails closed. This optional policy is
not present in the current authorization; no model request is authorized by
the code change or the daily export alone.

### DeepSeek native CNY staged capacity

Direct DeepSeek uses the existing `ONE_PROVIDER_CALL` staged authorization.
The signed Mission budget and shared risk envelope remain USD; they are not
claims about the provider wallet. Every DeepSeek reservation must additionally
pass a native CNY capacity check before a request can be sent. OpenAI capacity
and the frozen Direct transport are unchanged.

The funding policy selects `currency: CNY`, `safety_margin_microcny`, and
`unit_upper_bound_microcny` for both existing stage classes. It binds the exact
`direct_transport_identity` and a `native_price` attestation with provider
`deepseek`, currency `CNY`, model `deepseek-flash`, and positive integer rates
`input_cache_miss_microcny_per_million` and `output_microcny_per_million`.
The signing authority must verify those rates against the existing hash-bound
pricing source. No USD/CNY conversion or historical average is accepted.

With rates A and B in micro-CNY per million tokens, the exact integer bound is
`ceil((A*1048576 + max(0, B-A)*90000)/1000000)` micro-CNY per invocation.
Both stage-class bounds must equal that value. Reasoning is already included
in completion. Cache discounts do not reduce this bound. Qualification has
four ordered cases, but the staged gate checks one call at a time; it does not
require a wallet to prefund four cases or the entire 100-call Mission.

The separately signed snapshot retains the existing version, account,
credential, source hashes, authorization/policy hashes, epoch, validity period,
settlement coverage and checkpoint binding. It specifies provider `deepseek`,
`unit: CNY`, `amount_semantics: CURRENT_AVAILABLE_NET_BALANCE`, and nonnegative
integer `available_microcny`, `unsettled_liability_microcny`, and
`other_allocations_microcny`. USD amount/conversion fields are rejected on this
native path. The official and settlement sources remain mandatory; no FX
source is needed. Missing, stale, altered or incompatible evidence fails closed.

Only exposure not yet reflected in the snapshot's authenticated settled prefix
is deducted from its net available balance. Settled history is not deducted
again. Insufficiency produces the existing funding pause with explicit CNY
amounts, before consuming a call or attempt. Manual snapshot refresh preserves
all requests, debits, history, UNKNOWN states and the Mission clock, and does
not change the Qualification binding. Runtime/model/contract/target identity
checks continue to apply. No top-up, balance collection or live authorization
is performed by this feature; current official native pricing and balance
attestations must still be supplied before live execution.

For native CNY execution, the signed funding policy can select
`no_overdraft_policy: OPERATIONAL_PRE_SEND_SAFETY/v1`. This contract does not
require an absolute provider promise that an account can never overdraw.
It omits `provider_no_overdraft` and the `no_overdraft_source_*` fields.
Pricing and physical-bound source hashes remain mandatory. The native bound
and exact frozen Direct identity remain bound to the signed authorization.
The approved margin must equal `(unit_bound_microcny * 10 + 99) // 100`;
no balance-based adjustment or floating-point rounding is accepted.

Safety is operational: a fresh official net balance must cover the next
physical invocation plus this margin before an atomic reservation. The frozen
Direct adapter permits one HTTP attempt with max_tokens=90000, retry=0,
no redirect replay, repair or continuation. There is no automatic top-up.
HTTP 402 remains a failed, non-retryable invocation. Missing usage after any
possibly-sent request remains UNKNOWN, with its full reservation retained;
UNKNOWN or in-flight accounting blocks all later invocations and refresh.
Every later invocation revalidates staged capacity. Internal Mission ceilings
are unchanged, irrespective of wallet size.

Account-owner facts remain separately required: exclusive allocation, bounded
other allocations and unsettled liability, and authenticated settlement
coverage. Operational safeguards cannot generate these facts or default them
to true. The legacy absolute-proof policy is still supported when explicitly
selected with its original evidence, including on legacy USD paths.

### OpenAI current subscription availability

OA103 remains the internal Mission-wide call ceiling, not a provider quota
unit. A signed `openai_availability_policy` replaces full-future-envelope
provider capacity checks for OpenAI only. Internal call, token, cost, reasoning
and wall-clock gates remain independent. No percentages or historical usage
are converted to future calls; availability promises no number of future calls.

The policy fixes the canonical Codex binary, CODEX_HOME, `codex_subscription`
route and `gpt-5.6-sol` model. Signed availability evidence binds that policy,
authorization, account, credential, source hash, evidence domain, monotonic
epoch and bounded observation/expiry times. It requires boolean
`subscription_active`, `membership_active` and `known_capacity_blocked` fields.
Missing, stale, inactive or blocked availability pauses before send; mismatched
identity or altered evidence fails closed. Every invocation rechecks current
availability, including immediately before starting Codex. Historical window
percentages alone cannot authorize execution. Evidence collection is external.

An explicit native subscription/quota exhaustion failure produces
`PAUSED_SUBSCRIPTION_UNAVAILABLE`, retains the failed attempt and its entire
reservation, and records a durable block. It is never a successful result;
there is no automatic retry, account/model switch or API fallback. Generic
transient rate limits retain their existing classification.

Fresh signed evidence may clear the known availability block only at a legal
checkpoint, preserving all requests, attempts, debits, UNKNOWN and the Mission
clock. Refresh does not change Qualification identity. In-flight, UNKNOWN,
unverified or over-reservation usage still blocks refresh: availability cannot
reconcile consumption. In particular, a failed Codex turn lacking usage remains
UNKNOWN and cannot resume merely because subscription availability recovered.

For fully accounted subscription pauses, Qualification retains completed cases
and archives the failed case artifacts before continuing that same case and
run. Existing semantic cases and success checks are unchanged; an interrupted
suite cannot pass. Recovery is bounded to two attempts per case and at most two
capacity failures overall, with every invocation still debited against OA103.
Runtime/model/contract/target binding continues to require new Qualification
when changed. No real quota access or live authorization occurs in tests.

### OpenAI Codex terminal usage

Formal OpenAI execution persists the bounded raw JSONL, stderr, and final
response before ephemeral cleanup. An HMAC-bound manifest links them to the
active request, authorization, runtime/model, prompt and command hashes.
Settlement re-reads these files and verifies the single completed thread/turn,
agent-message identity and final response against the terminal usage.
Codex `input_tokens` includes `cached_input_tokens`; the ledger stores disjoint
input/cache categories. `reasoning_output_tokens` is included in output, never
charged a second time. All four fields must be explicit nonnegative integers;
missing or malformed categories remain UNKNOWN and block later requests.

This capture fix does not reconcile prior UNKNOWN usage, refund reservations,
or introduce a continuation authority. Existing UNKNOWN history still blocks
refresh and runtime identity updates under the canonical delivery contract.

### One approved request #5 continuation

`cmh-request5-reserved-unknown-continuation/v1` permits only the explicitly
approved frozen five-request predecessor. Production pins its ledger and #5
row hashes. Its signed checkpoint, authority, complete request prefix, full
reservations, consumed counts (DS4/OA1/global5), and remaining call ceilings
(DS96/OA102/global198) must match. No predecessor send may be in flight.

The canonical continuation builder writes a separate fixed ledger containing
all predecessor requests unchanged. It preserves their usage, status, cost,
tokens, attempts and durations; the authority inherits the original start,
expiry, wall-clock and budgets. Old capacity references are archived and fresh
checkpoint-bound evidence is required. Old Qualification identity cannot be
reused after the runtime/authority transition.

Only that exact immutable #5 row is exempt from the unresolved-history launch
block. Its UNKNOWN and unverified accounting never become resolved or zero;
its full reservation is never refunded. Any changed historical row, another
UNKNOWN, new unverified usage, in-flight send or overage remains fail-closed.
The predecessor and old #334 ledger are never rewritten. This is one approved
transition, not an arbitrary ledger migration or UNKNOWN reconciliation.

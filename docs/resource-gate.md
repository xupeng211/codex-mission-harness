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

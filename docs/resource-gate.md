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

Set `CMH_RESOURCE_AUTHORIZATION`, `CMH_RESOURCE_AUTH_SHA256`,
`CMH_RESOURCE_GATE_KEY_FILE`, `CMH_RESOURCE_LEDGER`, and
`CMH_RESOURCE_MISSION_ID` from the trusted controller. The controller must also
provide `CMH_RESOURCE_FREEZE` and `CMH_RESOURCE_FREEZE_SHA256` for a signed
snapshot of the settled request prefix. Removing or changing a frozen request
cannot restore capacity. Review and
qualification runners set the run ID; stage invocations set the stage ID.
Missing, altered or pending context denies the request before `Popen`.
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

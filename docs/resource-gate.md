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
`CMH_RESOURCE_MISSION_ID` from the trusted controller. Review and
qualification runners set the run ID; stage invocations set the stage ID.
Missing, altered or pending context denies the request before `Popen`.
OpenAI Codex, DeepSeek Reviewer V2 and both qualification paths call this
gate. A nested Codex call inside one qualification case shares that case's
reservation, so it adds only one logical request.

Each call debits its full approved input, output, reasoning, cache and cost
reservation before launch. The debit remains after success, failure or
missing usage. Reported usage and CLI USD metadata are stored separately;
they are not confirmed bills. DeepSeek cost estimates use the signed peak
price table and reported token counts; CLI USD metadata is never treated as a
bill or compared to the USD reserve. A token or price-based estimate above its
reserve blocks later calls. Resume reads an already committed review stage
without invoking the model, so it makes no new reservation.

**Limit of this contract:** The existing Codex CLI does not expose complete
input, output and hidden reasoning token usage, and neither current CLI path
proves a provider-enforced per-call Token cap. Fixed reservations therefore
provide a user-approved conservative *accounting* bound across calls, not a
guarantee that one physical call cannot exceed its reserve. The user must
explicitly approve this UNKNOWN-usage policy or require a metered/capped
transport before live review. A single observed overage is retained and
blocks subsequent calls; it cannot be retroactively undone.

Current Stage A has **no approved Token or cost artifact**. The existing
call/wall approval alone cannot pass the gate. Never sign a proposed budget
until the user separately approves its numbers and accounting semantics.

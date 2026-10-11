# One successor for the fixed failed PR2 Fresh Task

This is a second and final bounded edge of the existing delivery contract, not a
resume, settlement, refund or general recovery service. No real execution is
authorized by implementing this module or by creating a draft.

The production parent is exclusively
`HARNESS_PR2_FRESH_feb176100bf42820f7fcf39705961ad1e80cd468082679e5c7927400b49724fb`.
`fresh_task.py` pins its signed grant, complete ledger and checkpoint, whole
UNKNOWN row, and original diagnosis/raw transport hashes. The parent must still
be an ordinary `cmh-fresh-pr2-task/v1`, with precisely its first GPT Qualification
slot FAILED/UNKNOWN and claimed transport. It cannot be another successor or a
different timeout/failure. The original 120-row/eight-UNKNOWN history and parent
UNKNOWN stay byte-for-byte unchanged and fully charged to shared accounting.
The parent need not first expire: it is already permanently unable to send
because of UNKNOWN, and the new explicit approval must separately authorize
abandoning that execution without declaring it settled or closed.

The new signed envelope uses the existing authorization/signing machinery and a
`fresh_task` descriptor with version `cmh-fixed-failed-pr2-successor/v1` and an
exact `successor` disposition. Its separate approval version is
`cmh-fixed-failed-pr2-successor-approval/v1`. Mission IDs use
`HARNESS_PR2_SUCCESSOR_` plus the new exact approval hash; execution IDs use a
distinct successor domain. The same target overlap approval, independently
approved budget/time/account credentials, final runtime HEAD/file/registry hashes,
exact PR2 HEAD/tree/source scope/manifest and canonical seven-slot-per-provider
request plan remain mandatory. Credentials changed by reauthentication must be
newly bound, not substituted into the old grant. Previous Qualification and
receipts are never inherited.

The approval additionally accepts the explicit states
`PARENT_UNKNOWN_RETAINED_NOT_SETTLED`,
`GPT_QUOTA_UNKNOWN_NO_ADDITIONAL_PURCHASE`, and
`PROVIDER_PHYSICAL_COST_HARD_BOUND_UNPROVEN`. These are disclosures, not proofs of
settlement, quota or Provider bill limits. Bounded official read-only GET
permission is independently included in that exact signed approval (at most nine
logical and ten physical GETs, no automatic retries). It is a permission ceiling,
not a proof of physical Provider fees; the existing controlled read-only caller
must count actual attempts and stop before exceeding permission. This change
does not add a GET client or perform any GET.

The successor ledger path is deterministically derived from the frozen parent
ledger hash under the existing private task root, independent of mission name,
worktree, approval, run ID or execution ID. Activation holds the existing shared
ledger lock and creates a private HMAC-bound `.activation.json` file using
O_EXCL/O_NOFOLLOW. The claim and directory are fsynced before any checkpoint or
ledger writes. Every subsequent child verification requires the matching claim.
Concurrent activation has one winner. Repeated activation, a renamed or copied
ledger, another approval, or a process restart cannot create another successor.
A crash after claiming, including a partial claim/journal, stays fail-closed; it
does not authorize recreating the task. Successful execution may reuse verified
artifacts through existing Durable Resume, but it never reinitializes authority.
Deleting trusted persistent evidence is not a permitted administrative operation.

No successor-of-successor is accepted, regardless of success, failure, expiry or
UNKNOWN. New failed/UNKNOWN/in-flight rows still block every next slot, funds
refresh and transport claim. A second real attempt after this successor has no
automatic recovery path. There is no new authoritative CLOSED state for the old
task: only an independently approved read-only parent disposition.

Existing shared call/token/cost ceilings include the 334-row original ancestor,
120-row later history and the failed parent's full reservation. The new ledger
contains only new slots; historical usage is not counted as a new request or
claimed as a successful result. The current account capacity attestation and
native wallet/settlement evidence must bind both the 120-row history hash and
`successor_parent_ledger_sha256`. The operational pre-send CNY policy, retained
native UNKNOWN exposure, fresh official balance and owner/liability facts,
manual-top-up-only restriction and subscription availability remain in force.
Production snapshots cannot be older than the approved policy (at most 300
seconds). This does not make unknown liabilities zero or prove a hard bill cap.

The existing Provider Sender requires current signed authority, matching live
reservation, exact prompt, model, credential and ledger, and a durable one-send
claim. Offline signatures/reservations cannot cross transport. Source Binding,
receipt schemas, Qualification validators, and the two-receipt canonical Consumer
are unchanged. GPT completes first; the execution controller must require its
legal semantic PASS receipt before starting the independent DeepSeek inputs.
Returned slots alone do not authorize DeepSeek after a semantic FAIL. No findings
from one model may be supplied to the other.

Tests adapt the read-only real 401/UNKNOWN evidence into isolated, explicitly
OFFLINE_TEST signed fixtures. Their identities/timestamps and fixture keys are
synthetic; production keys are not used. A fixture Consumer PASS is not a real
review receipt or live Qualification. Full production validation rechecks the
fixed hashes using the historical signing trust anchor, final runtime and fresh
financial evidence. A later real run still requires separately approved exact
models, prices/budget, GET/POST/CLI limits, expiry and disclosed remaining risks.
PR2's source stays frozen; no push/CI dispatch/merge is implied by this contract.

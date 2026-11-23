# Software delivery factory architecture

The completed architecture audit is an input, not reopened here: this is an independent Python governance harness, not an OpenAI Codex fork. Reviewer V2 had medium/high execution duplication. New missions use a factory loop, not another review framework.

```mermaid
flowchart TD
    A[Customer product request] --> B[Durable mission and authority]
    B --> C[Official Codex technical lead]
    C --> D[Official Codex implementation threads]
    D --> E[Exact Git checkpoint]
    E --> F[Tests and local CI commands]
    F --> G[OpenAI: official rubric + structured turn]
    F --> H[Independent DeepSeek API review]
    G --> I[Evidence and delivery gate]
    H --> I
    I -->|Findings or failed tests| J[Official Codex rework]
    J --> E
    I -->|All required evidence proven| K[READY_FOR_USER_ACCEPTANCE]
    K --> L[Human acceptance and explicit approval]
```

There is no merge/release executor after L. The customer does not schedule agents or repair ordinary engineering failures.

## Components and responsibilities

| Responsibility | Implementation |
|---|---|
| Product goal | Immutable v2 mission: repo/base/objective/acceptance/constraints/scope |
| Technical lead | Official Codex turn with bounded plan, tasks and genuine product decisions |
| Development agents | Fresh official Codex thread per task, sequentially editing an isolated candidate |
| Rework | Official Codex debugging turn with test/CI failures and findings, bounded rounds |
| Tests / CI | Existing project commands through reused bubblewrap isolation; verified exit codes |
| OpenAI review intelligence | Unmodified upstream rubric + App Server `outputSchema` |
| Independent second opinion | Direct DeepSeek HTTPS API, separate credentials/context, no prior lane conclusions |
| Evidence / budget / recovery | SQLite reservations, immutable completed accounting, append-only audit, hashed raw files |
| Delivery / authority | Reconcile target and gates; exact-HEAD human approval; no merge/release executor |

`factory.py` contains mission governance, `factory_runtime.py` thin invocations, `factory_cli.py` the customer interface, and `factory_fixture.py` cost-free acceptance. Existing `codex.py` protocol/security helpers and `sandbox.py` are reused. No workflow DSL, plugin platform, generic review framework or custom subagent runtime was added.

Private factory state is separate from historical `data/harness.sqlite` and formal ledgers. Candidate Git databases are independent clones without origin remotes, object hardlinks or alternates. Source refs/history remain untouched. Each review lane gets its own exact-head repository copy.

## Why an official-rubric structured turn

Official App Server supports `review/start` and `turn/start.outputSchema`. The installed Codex 0.159.2 schemas were generated and inspected. `review/start` exposes rendered `exitedReviewMode.review`; upstream review parsing can fall back from unparseable JSON to explanation with default findings. Treating rendered prose as an empty PASS would weaken this harness.

The replacement therefore uses the exact official rubric as `baseInstructions`, the official repository/tools/model runtime, and the official finding schema through `outputSchema`. Harness validates the result without reproducing review reasoning, priority classification or synthesis. The upstream rubric, Apache license, NOTICE and commit/hash provenance are vendored; the rubric is integrity-checked. This is genuine source reuse without claiming to be a Codex fork.

Official sources: [App Server](https://developers.openai.com/codex/app-server/), [permissions](https://developers.openai.com/codex/permissions/), [configuration](https://developers.openai.com/codex/config-reference/). Exact upstream provenance: `src/harness/vendor/codex/provenance.json`.

## Exact scope and independent evidence

Target identity includes canonical repository, immutable base, head/commit, tree, customer file scope, complete changed paths and full binary Git diff hash. The base must be an ancestor. Dirty/untracked source cannot be tested, reviewed or delivered. Optional committed project scope authority must retain its original blob.

Tests, CI and both reviews bind to that target. Official-format finding paths must be canonical and inside the lane repository, committed line ranges must exist, and locations must overlap the exact diff. Removed-file references bind to the base blob and also identify the delivery head. Missing, malformed or contradictory results never PASS. All actionable findings trigger rework without an adjudication ladder.

OpenAI review has a fresh official thread without implementation history. DeepSeek receives product requirements, full diff and bounded tracked text context, never OpenAI's results. Same-provider agents cannot satisfy independence. Oversize inputs stop; partial/chunked payloads cannot claim complete coverage. Changed submodules cannot be certified from gitlink hashes alone.

## Profiles and accounting

Model/profile identity is lane-local. OpenAI uses official selected configuration unless explicitly selected; runtime model/provider identity, config hashes, version and raw events are preserved. DeepSeek uses its official HTTPS endpoint and must return the configured model and a non-truncated completion. Changing one review profile creates evidence only for that lane; the other provider's receipt and all accounting remain immutable. Same-target review refresh does not authorize rewriting delivered source. Changing the code head correctly requires both providers to review the new target.

Operator authority fixes run budget, timeout, rework rounds, commands, capacity and independence at mission creation. It cannot increase on resume. SQLite transactionally reserves before dispatch. Failure/UNKNOWN consumes its run reservation. Completed accounting cannot be edited, deleted or refunded. Historical UNKNOWN is never backfilled from later requests.

`budget.max_plan_tokens` optionally sets the planning observation threshold. Omission
retains `min(max_run_tokens, 32000)` (32000 for legacy call-only budgets); an explicit
value must be a positive integer, not a boolean, and requires an authorized
`max_run_tokens` at least as large. It is part of the immutable mission policy:
adding, removing or changing it cannot resume an old mission under new authority.
For example, a newly authorized budget with `max_run_tokens: 120000` and
`max_plan_tokens: 96000` uses 96000 for planning; this is an opt-in policy choice,
not a new default or a promise that a real plan will complete. Runtime and retained
result checks share `planning_limits`; planning remains bounded to 120 seconds
and the remaining mission authority. Other stages and UNKNOWN reservations are
unchanged. Token observations are cumulative input plus output, with cached input
included once. Notifications may arrive after an overrun: neither this threshold,
native rollout configuration nor logical reservations guarantee a physical token
ceiling, internal request count, subscription usage or monetary limit.

Planning receives Controller-observed BASE, dispatch HEAD, branch and whether the
candidate actually has remotes. These dispatch facts do not invalidate a completed
plan's cache key after a later implementation checkpoint; they are retained in
the durable operation input and evidence envelope for the original dispatch.
Reading guidance avoids
reprinting instructions only when their automatic loading and same version are
confirmed; missing/changed instructions, required workflow documents, applicable
nested rules, scope, authorization and acceptance remain mandatory. It encourages
batched independent reads and targeted excerpts without changing tool permissions
or supplying the plan on the planner's behalf. Actual token savings remain unproven
until a separately authorized real trial.

### Planning handoff contract

Keep preparation status and execution authority distinct in the existing mission
`constraints`. Before freezing a future execution input, the Controller must
verify the real Owner source and its exact versions, scope, budget and window,
then replace preparation-only/pending wording with a consistent statement of
those verified facts. Do not append an approval claim while leaving contradictory
pending wording elsewhere. If an approval binds input hashes, the final execution
bytes and hashes need to be covered by that approval; do not rewrite already
frozen inputs. An external record that the planner cannot read is not a substitute
for these input facts. This is a Controller preparation responsibility: Factory
passes constraints through and binds them in the operation input/evidence, but
does not authenticate human approval or interpret a new generic approval schema.
The prompt never grants approval. Missing or conflicting authority remains a
genuine `decisions_required` blocker, not something to infer from user tone.

The PLAN session is intentionally read-only and receives no writable temporary
workspace. Later implementation uses separate sessions; the existing runtime
allocates and checks authorized candidate writes and private temporary resources
for those writable sessions. PLAN's current permissions alone are not evidence
of a Builder defect. This explains the role boundary, not a claim that the future
Builder environment has already passed. Concrete permission conflicts or missing
prerequisites must still be reported. No permissions, TaskTemp or sandbox rules
change as part of this handoff contract.

The four-field `PLAN_SCHEMA` is unchanged. `tasks` is a machine dispatch list:
each entry becomes one separately charged implementation assignment, including
its corresponding product regression tests. It is not the complete delivery
workflow. Harness validation, independent review, Controller checkpoints and
PR/release work do not belong in that list; describe the verification route in
`plan`/`acceptance` instead. Task count may vary by project and must fit remaining
implementation plus configured review operations. Existing malformed-plan,
nonempty-decision and over-budget checks still stop before implementation; no
decision or returned task is silently removed or compacted. Return the complete
plan once locations, requirements, authority, bounded work, verification and real
unresolved facts are clear; planning does not execute tests or perform review.

Compatibility: the operation key hashes the prompt before adding dispatch-only
workspace facts. This instruction change therefore gives a different plan key
from the previous prompt. An unchanged prompt still reuses its verified completed
result after a checkpoint. The real `Factory.agent` planning dispatch attaches
an existing operation `prepare` hook: after cache, cancellation, uncertainty and
preflight checks, a plan-key miss checks for COMPLETE plans in the same mission
before any new reservation or transport. The generic low-level operation budget
primitive is unchanged; it does not itself identify a real planner from a stage
label alone. Historical envelope/raw hashes and envelope-to-operation binding
must verify; missing, changed or misbound planning evidence stops as UNKNOWN.
With valid historical evidence, a different plan key stops as BLOCKED_LIMIT,
including WAITING_PRODUCT_DECISION and intermediate implementation/test/review
resumes. A repeated run remains stopped; it cannot buy a new plan or repeat
implementation by missing the cache. Matching-key plans retain verified reuse,
and already READY deliveries retain their existing exact-evidence checks.
This patch does not migrate receipts, rewrite plans, change old accounting or
provide paid replanning/recovery authority. Old UNKNOWN/RUNNING, cancellation
and budget protections remain. Any future execution needs consistent,
explicitly authorized frozen inputs and a separately decided compatibility path;
this patch supplies no recovery mechanism or new spending authority. Offline
fixtures prove transport/evidence/dispatch and rejection behavior, not future
model understanding, planning success or business delivery.

### Ordered implementation checkpoints

Before submitting a staged mission, set `implementation_checkpoints: true`
and list the required output paths for each nonfinal assignment in
`implementation_checkpoint_outputs`. For two assignments, an example is
`[["src/service.py", "tests/test_service.py"]]`. Both settings are part of
the immutable mission policy. List dependent assignments in execution order.
Each required output must be a regular tracked file within the mission scope,
with content that changed in its assigned segment. The operator's existing
`checks` must cover the behavior the next assignment needs.

After each nonfinal assignment, the Controller commits its changes, verifies
the required outputs, and runs the configured checks for that exact target.
Generic checks run in a fresh checkout of that commit. Project validation
keeps its existing executor. After a pass the Controller reports
`IMPLEMENTATION_CHECKPOINT` with the target, required outputs, and the keys
of the implementation and check evidence. The existing `resume` command
advances to the next assignment. The CLI exits nonzero at a checkpoint because
final delivery is pending.

On resume, the Controller verifies completed assignments, committed outputs,
check logs and the physical checkout before reserving the next operation.
Uncommitted inputs, including ignored files, block continuation. Work that
needs generated files should use the existing temporary workspace. Historical
checkpoints without an approved output policy cannot advance. An interrupted
assignment without a durable checkpoint, an unknown result or a changed
candidate retains its evidence and accounting. Missing outputs or failed
checkpoint checks stop with `BLOCKED_VALIDATION`. The run-count precheck
counts assignments still to dispatch and the configured review lanes even
when the policy specifies only a call limit. Token and wall-clock admission
continue to use the original rules.

After the last assignment, the regular final tests, CI, independent review and
applicable PR gates still cover the cumulative BASE-to-final-HEAD changes.
The single-task, local-candidate and rework paths retain their flow.

Budget units are agent executions, not dollars or internal Codex model requests. Native subagent fan-out is disabled to avoid an unregistered execution tree; role/task threads still use the official runtime. Real money remains UNKNOWN; Provider account limits are necessary for a monetary ceiling. Fixture telemetry explicitly records zero real Provider calls and cannot become a formal receipt.

Known completed results are reused after envelope and raw-file hash verification. A proven completed malformed review allows one separately charged validation attempt. Lost requests never automatically replay. Controller death with a reservation but no trustworthy completion is UNKNOWN. A published implementation receipt can recover its pending Git checkpoint without repeating that paid execution. A per-mission POSIX lock prevents concurrent controllers from racing source/dispatch. GNU `timeout` also bounds the App Server process independently of controller reads; controller death cannot leave an unlimited paid runtime.

## Safety and delivery

Constructor-bound official permissions allow developer source edits and keep Git metadata read-only. Planner/reviewer have a minimal repository/runtime read profile. Original source, controller/evidence storage and authentication are unavailable to delegated tools. Network is disabled; approval requests are denied. Existing trusted launcher/PATH and environment allowlists are reused.

From the Owner's 2026-11-01 boundary decision, writable delegated sessions use only their exact candidate and a Controller-allocated private temporary workspace. Both roles use the minimal repository/runtime profile; neither inherits the built-in `:workspace` host-temp grants. Developer scratch is bound to the canonical worktree and fresh permission profile, outside the candidate and protected roots, and verified before reuse and cleanup. Shared host `/tmp`, other sessions' scratch and candidate-selected paths are not delegated. Read-only roles receive no writable scratch. See [the temporary workspace contract](DELEGATED_TEMPORARY_WORKSPACE.md) for lifecycle, failure and recovery limits. This new rule does not reclassify historical reviews or authorization.

### Native delegation and usage compatibility

Codex 0.164.0 still recognizes the legacy `features.multi_agent` and
`features.multi_agent_v2` fields, but its native collaboration instructions
remain present with those fields false. The adapter also sets the documented
`agents.enabled=false` at process startup and in the thread configuration.
Offline native configuration checks and prompt rendering verify those inputs;
they do not prove that a real Provider turn will finish successfully.

Each adapter invocation binds one fresh thread and its accepted turn before
using token telemetry. Notifications retain their thread/turn attribution;
foreign activity or native delegation stops execution as UNKNOWN. If a usage
notification precedes the turn/start response, it is retained and matched to
the accepted turn before affecting the cutoff. Unexpected delegation can
already have incurred work when its notification arrives, so this guard is
not a physical spending guarantee.

`usage_telemetry` preserves per-thread/per-turn cumulative snapshots in the
existing operation evidence, including on failure. A snapshot's `total` is
not a turn delta; `last` is not added to `total`, and cached input is already
included in input. Parent/child snapshots are never summed as a bill. Failed
execution still retains the original full reservation alongside attributable
partial usage. No historical accounting is rewritten or settled by this fix.

An independent patch review may instead use a manual Controller with the
official App Server `thread/start` and `turn/start.outputSchema` interfaces,
the pinned rubric, the existing direct DeepSeek worker and exact-source
validator. It need not invoke `Factory` or this adapter. Such evidence must
identify its actual path; it is not a Factory delivery receipt, and does not
demonstrate autonomous Factory orchestration. Native telemetry and rollout
budgets cannot establish a physical cost hard cap.

Configured MCP/plugins are explicitly disabled: empty TOML tables merge and do not clear inherited servers. Hooks/apps are disabled. The cwd is the verified Git root, so parent project-root probing is disabled while repository instructions remain available. Tests reuse bubblewrap: clean env, no network, read-only source/Git metadata, sanitized Git config, private logs. Missing isolation fails closed.

Only proven local tests, configured CI commands, required reviews and final target/evidence reconciliation produce READY. Read-only status also rejects stale HEAD or changed evidence. Major product decisions, budget exhaustion, capacity and uncertainty produce explicit blockers. Human approval records exact target and reason; no automatic final merge/release code exists in the factory. Fixtures cannot receive live approval.

## Deprecated execution and safe replacements

| Retired responsibility | Safety-preserving replacement |
|---|---|
| Byte-chunk DAG; fixed 21/7/group=3 | Full diff and source exploration; explicit capacity failure |
| Groups and multi-level synthesis | One full-target official-format result per lane with raw evidence |
| Generic custom reviewer prompts | Unmodified pinned official rubric and transport schema |
| Custom severity/finding intelligence | Official priority/correctness, only evidence/shape validation locally |
| Mandatory disposition/adjudication | Direct bounded rework, retest and full rereview |
| Generic subagent lifecycle | Official thread/turn lifecycle with small mission task dispatch |
| Group-dependent source identity | Git paths, committed blobs, lines and exact target |
| Global qualification invalidation | Lane-local profile keys; unrelated provider evidence preserved |
| Hardcoded OpenAI model pins | Official configuration and recorded actual runtime identity |
| Identity-exception machinery | No chunk/group/synthesis identities in the new pipeline |

Legacy scripts/modules remain explicitly deprecated compatibility and regression-test subjects. Their historical receipts/UNKNOWN are not reinterpreted. New factory execution does not depend on old reviewer scheduling, manifests, group blockers, synthesis or qualification publication. Old CLI execution needs `--legacy`; live legacy auto-merge is rejected. The existing group blocker remains history, not a new delivery dependency.

Active runtime complexity is lower. Repository size temporarily increases because historical compatibility code is intentionally retained; retirement does not require erasing old source/evidence.

## Pilot limits

This is a local Linux factory, not a hosted service. It does not automatically publish PRs, push, poll hosted CI or deploy. Local configured CI PASS is not a GitHub status claim. Authentication/model access and project dependencies must exist. Read-only gates need build outputs in configured temporary locations. Oversize DeepSeek context, binary changes and changed submodules stop explicitly. App Server remains experimental; installed-version offline compatibility is checked, and live inference qualification remains a pilot activity under separate budget authority.

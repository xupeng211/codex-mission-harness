# Factory migration validation — 2026-10-07

Status: **READY_FOR_USER_ACCEPTANCE for the implemented local factory / controlled pilot**. This is not a claim of production-qualified live review or successful hosted CI.

## Test evidence

| Verification | Result |
|---|---|
| Baseline governance suite before migration | 426 tests, PASS |
| Final `make verify` | 481 tests, PASS; 55 new tests; compile checks PASS |
| Installed official Codex | 0.159.2; real initialize/thread/permission/command protocol, no model inference |
| Native runtime tests | Source access, controller/auth/original isolation, Git read-only, reviewer read-only, inherited MCP/hooks disabled, independent wall-clock watchdog |
| Real project-gate sandbox | bubblewrap execution PASS; source mutation denied; exact commit retained |
| Package | 0.2.0 wheel built and installed in a separate directory; upstream rubric/LICENSE/NOTICE/provenance included |
| Installed-package E2E | Complete factory loop PASS, original fixture repository byte/HEAD preservation |
| Python | 3.14.4 runtime tests PASS; source syntax compatible with 3.11; hosted CI matrix configured for 3.11 / 3.14, not executed remotely |
| Historical local files | Pre-migration inventory unchanged; no legacy database/ledger conversion or UNKNOWN backfill |
| Existing branch refs | No changes to original branches/remotes; only a separate migration branch is used |
| Real Provider inference | 0; no formal PR2/PR4 review, no Provider budget authority expanded |
| Merge / release / push | Not performed |

Final verification log in this workspace session: `/tmp/factory-final-verification-2.log`. Package build/install logs: `/tmp/factory-delivery-wheel.log`, `/tmp/factory-delivery-install.log`. The wheel is `/tmp/codex-factory-delivery-wheels/codex_mission_harness-0.2.0-py3-none-any.whl`.

The local pre-migration file inventory contains the two existing mission files. No claim is made that absent historical external ledgers were recreated or requalified. Existing formal artifacts outside this checkout were not written, removed or used to fabricate new receipts.

## Acceptance: a customer asks for a small feature

Request: add `average(values)`, return 0 for empty input, preserve fractional values, and preserve existing `add` behavior.

Observed installed-package sequence:

```text
mission submitted
→ plan
→ implement (deliberately incorrect integer division)
→ real tests PASS (existing cases miss fractional behavior)
→ local CI command PASS
→ separate OpenAI / DeepSeek fixture review findings
→ automatic rework (true division + fractional regression test)
→ real tests PASS
→ local CI PASS
→ final full-target fixture review in both lanes PASS
→ READY_FOR_USER_ACCEPTANCE
```

Seven simulated agent runs were reserved against a limit of twelve. Real Provider calls and fees were not incurred; this does not reinterpret any historical UNKNOWN usage. The original source repository remained unchanged. Both review lanes inspected separate exact-target clones and received no previous findings.

The retained output is [FACTORY_ACCEPTANCE.json](FACTORY_ACCEPTANCE.json). Raw evidence and candidate source remain under `/tmp/codex-factory-acceptance-final-20261007/`. The artifact is explicitly **NON_CANONICAL / SIMULATION**, not a live Provider receipt or production gate certificate.

## Failure and compatibility coverage

New tests cover multiple implementation tasks, significant product decisions, test/CI-triggered rework, per-lane model changes, unrelated developer-profile changes, dirty or changed delivery heads, missing/corrupted envelope and raw evidence, exact changed-line findings including deleted base blobs, immutable committed scope authority, out-of-scope changes, complete-context capacity limits, budget exhaustion, failed/unknown usage, immutable accounting, bounded malformed-output recovery, controller crash before/after implementation publication, concurrent controllers, storage/runtime boundary attacks, genuine Provider identity, fixture/live separation, and human approval restrictions.

Original governance tests continue checking legacy exact-head validation, independent receipts, ledger/UNKNOWN semantics, owner approval, durable process identity, private evidence, permission boundaries, trusted invocation and protected production controls. One CLI test was updated to explicitly opt into `--legacy`; its constructor-bound safety assertion is unchanged.

## What is ready and what remains outside this pilot

After one-time operator configuration, a customer can submit a product request and receive a tested/reviewed/reworked **local candidate** without issuing prompts to agents. Ordinary engineering findings are handled internally; budget, scope, significant product choices and unknown dispatch remain explicit blockers.

Live OpenAI / DeepSeek inference has not been run in this migration. Model access, auth and project dependencies must be available. `CI_RESULT=PASS` proves configured local commands, not GitHub hosted checks. Automatic PR publication, hosted CI polling, deployment and final merge are outside the current local pilot. Large full-text independent contexts, binary changes and changed submodules stop rather than silently reducing coverage. Monetary usage remains UNKNOWN; run admission and wall-clock limits are enforced, while a dollar ceiling requires a Provider account limit.

The active factory path no longer depends on the historical group blocker, chunk/group/synthesis contracts, general prompt library, custom severity reasoning, mandatory adjudication or global review qualification. Deprecated source is retained for history/compatibility. No historical receipt was rewritten to claim that the new engine produced it.

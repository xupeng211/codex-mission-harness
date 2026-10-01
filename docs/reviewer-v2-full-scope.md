# Reviewer V2 full scope and evidence binding

This protocol prepares source without calling a provider. Offline tests never
qualify Reviewer V2 or authorize a merge.

## Git scope

At mission entry, origin/main is
`db0c931ea8ffd727a03513b25ae26ef2088d1a75`, PR #2 is OPEN at
`65c98f5f0e31eab4da2216860c20a39a2e02c70b`, and V2 is
`c7368bebca79520befbd4544ffd2a3daf42e0f18`.
Actual Git ancestry is main → 80 PR #2 commits → 19 V2 commits.
There is no local main branch or remote V2 branch at entry.
PR #2 ancestry is fully included; V2 subsequently modifies shared paths. This
is an ancestor dependency, rather than two divergent branches to merge in
reverse order. The PR #2 → V2 tree merge equals the V2 tree. The PR #2 increment
is only a V2 implementation scope, never the current full main candidate scope.

Recommended integration: independently review PR #2 against main first. After
an authorized integration of that dependency, fetch the actual resulting main
and regenerate V2's manifest and all review evidence against that main. Squash
or another integration method changes the Git objects and requires fresh
identities. Until then, V2's full scope is actual main..V2, including PR #2.
No integration or history rewrite is performed by this mission.

## Canonical source and resource bounds

`harness.full_diff_manifest` uses fixed Git diff flags: Myers, three context
lines, full blob IDs, explicit prefixes, rename threshold 50%, binary patches,
short submodule patches, no external diff or textconv, and fixed ordering.
Git replacements, global configuration and inherited environment are disabled.
The manifest records repository, full commit SHAs, merge base, source hash and
size, paths including lossless hex names, modes, blob IDs, change type, file and
hunk ranges/hashes, chunks, groups and policy versions. Its intrinsic hash is
canonical JSON excluding the hash field; the saved JSON file has its own hash.

Source is split into contiguous 32,000 byte chunks and groups of at most three
chunks (96,000 bytes). The full source ceiling is 4,096,000 bytes, 128 chunks,
and 64 groups. These are allocation bounds, not one enlarged model input. The
legacy 256,000 byte API remains unchanged. Long files, hunks, lines and UTF-8
boundaries can span chunks; exact bytes are preserved, with base64 rendering
where a fragment cannot decode. Separate location metadata supplies file/blob
and enclosing hunk identities, including for fragments that begin inside a
file. Repeated metadata is never counted as unique canonical coverage.

The independent validator reconstructs source and metadata from Git objects;
checks the intrinsic manifest hash; and checks the full exact range partition,
file coverage, chunk hashes, group layout and manifest-bound task assignments.
Assignments bind chunk ID, canonical range, exact source input SHA256, original
full diff hash and manifest hash. Preparation proves allocation only. Lane
validators additionally check every required result, dispositions, final
verdict and durable output hashes before a receipt is published.

Binary patches, gitlinks and non-UTF-8 source are explicitly represented and
block ordinary text review until a specialized review protocol exists. Text
additions, deletions, renames, mode changes and symlinks retain their modes and
blob identities. Neither unsupported content nor oversized inputs are skipped.

Each model prompt is limited to 192,000 UTF-8 bytes, each output to the existing
128,000 bytes. Excess source metadata or finding ledgers fail closed with a
budget error; necessary findings are never deleted to fit. DeepSeek's final
aggregation consumes the complete deterministic group ledger within this bound.
OpenAI uses batches of at most eight groups and deterministic higher levels.
Every level carries original finding IDs, severity, evidence and hashes as well
as summaries. All surviving original findings and new synthesis findings are
mechanically retained. Summary compression cannot remove a blocker.

## Qualification → execution → final gate (scheme B)

Qualification remains a capability/environment statement, independent of a
candidate's base/HEAD. Qualification v5 verifies role, provider/model/config,
registry, qualification runner/CLI, role review runner, invocation, schema,
case manifest, contract, full-scope implementation and HMAC integrity. An opaque
keyed authentication identity records the signing identity without storing
credentials. Launcher policy code is covered by invocation, registry and builder
runtime hashes; launcher trust/ownership is rechecked by existing invocation
preflight. No production credentials or qualification responses are copied into
full-review evidence.

Each signed full-review receipt contains the canonical qualification receipt
hash and a deterministic execution identity, binding repository, mission,
base/HEAD, full diff, full manifest, chunking policy, role/model/config,
registry, runner, invocation, schema and manifest implementation. Changing a
code version, scope, model or runner cannot reuse a prior full review.
Existing receipts lacking this protocol are rejected; qualification PASS alone
cannot substitute for full-review PASS.

The production final gate authenticates the actual qualification files and both
lane receipts/artifacts. It requires the base to equal `refs/remotes/origin/main`
and to be the candidate's ancestor. The operator must fetch origin/main before
review preparation; an offline gate cannot discover a newer remote main.
The gate rechecks this ref and source stability after validation. It compares
the qualification identity, execution, full manifest and complete chunk/group
allocation independently for both providers. Lane validators recompute all
required cross-group stages, findings, source references and final verdicts.
Any missing artifact, stale receipt or unresolved P0/P1/P2 blocks approval.

Resume identities now include full manifest, base/HEAD, diff, allocation,
chunking policy, implementation hash and review execution identity. OpenAI's
stage plan enumerates every synthesis level. Changed identity invalidates prior
state; committed stages reuse only matching inputs and valid artifacts.
Uncommitted stages reexecute; incomplete runs cannot publish PASS receipts.

## Offline preparation

```sh
python3 scripts/reviewer_v2_prepare.py --repo . \
  --base "$(git rev-parse origin/main)" --head "$(git rev-parse HEAD)" \
  --evidence /absolute/private/evidence/directory
make verify
```

Preparation emits canonical patch, manifest, task assignments, bounded chunk
files and coverage proof. It creates no review PASS receipt. Regenerate these
artifacts after committing; a precommit HEAD identity is not final evidence.
Tests use disposable Git repositories, blocked socket connections and explicit
mock invokers. Their qualification and review records are test fixtures only.

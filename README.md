# Codex Mission Harness v0.1

Harness is a small local supervisor for one primary Codex mission. It orchestrates existing project workflow; it never replaces a project's validators, Git/GitHub truth, approval policy, or production contracts.

## Stack and boundaries

Python 3.11+ standard library is used for durable SQLite state, POSIX process supervision and Linux portability. The Codex adapter starts the locally installed `codex app-server --stdio` and isolates JSON-RPC protocol details (`thread/start`, `thread/resume`, `turn/start`) in one module. A stored thread ID is resumed for subsequent turns; if the backend rejects a resume, that failure is explicit rather than silently presented as the original thread.

`data/harness.sqlite` is an orchestration journal/cache. Git exact HEAD, GitHub checks, project canonical gates and production gate artifacts remain source of truth. Resume always reconciles them before deciding the next transition.

## State machine

`CREATED → PREPARING → IMPLEMENT → TEST → REVIEW → CI → MERGE → POST_MERGE → DELIVER → PASS`.

Only `PASS`, `BLOCKED_EXTERNAL`, `BLOCKED_POLICY`, and `FAILED_FATAL` are terminal. Invalid transitions fail closed. Natural-language output such as “incomplete” or “done” is journaled but cannot terminate a mission.

## Run and resume

```bash
harness run missions/my-mission.json
harness status my-mission
harness resume missions/my-mission.json
```

Mission specs are versioned JSON, intentionally not a workflow DSL. They identify the repository, objective, required gates, review/merge policy and forbidden actions.

## Supervision and isolation

Commands are registered before execution with mission, argv, PID, process group, `/proc` start time and separated stdout/stderr paths. A running registered process is pending—not a blocker or completion—and is never started again under the same mission/gate name. After restart, missing or PID-reused processes become explicit `LOST`, never assumed successful.

Each writable mission worktree is created from `origin/main`, records base SHA/branch/path, and only reuses its exact recorded path. Docker receives a deterministic unique `COMPOSE_PROJECT_NAME`; no collision path deletes an existing container, network or volume.

## FootballPrediction adapter

The adapter calls only its canonical commands (`make verify-targeted`, `make verify-pr`, `make verify-strict`, `make agent-preflight`) and asks the project workflow for independent reviews. It does not contain quota, candidate, authorization, provider or live-request logic. In particular, this project does not invoke FootballPrediction Stage D or provider traffic.

## Approval and review rules

Source fixes, local gates and in-scope review/CI repairs auto-continue. Live providers, quota/spending, protected production changes, credentials, unknown-resource deletion and owner-controlled merge require persistent approval decisions. Review receipts are exact-HEAD-bound; reconciliation invalidates both Codex and DeepSeek receipts whenever HEAD changes, forcing fresh validation/review.

## v0.1 limits

No dashboard, worker cluster, workflow DSL, swarm, plugin marketplace or cloud platform. GitHub querying and project-specific merge/production execution require authenticated adapter implementations; missing canonical evidence remains pending/blocked rather than fabricated as PASS.

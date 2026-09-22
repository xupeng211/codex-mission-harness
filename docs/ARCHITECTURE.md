# Architecture

`CLI → Supervisor → Codex App Server / process runner / project adapter → canonical project workflow`.

The supervisor owns lifecycle and a SQLite event journal. The project adapter owns command selection and interpretation only by delegating to the target project's canonical entry points. A gate is passed only by an observed command, receipt, artifact or external API result; agent prose is never evidence.

For restart recovery, the supervisor reads its journal, checks the worktree exact HEAD, invalidates stale receipts, observes registered process identity, and then resumes the stored Codex thread. It does not replay completed gates or recreate a worktree just because the supervisor process restarted.

Docker isolation is additive: a mission gets `cmh-<sanitized-id>-<hash>`. Cleanup is intentionally excluded from v0.1 except for resources positively identified as mission-owned.

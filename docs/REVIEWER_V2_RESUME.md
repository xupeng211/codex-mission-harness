# Reviewer V2 durable resume

The standalone V2 runners use the existing private evidence directory and its
atomic, fsynced artifact writer. Each run has `state.json`, stage artifacts, an
optional failure artifact, and one receipt. The evidence root has an advisory
`flock` lease. The kernel releases it after process death; the state records the
current PID, Linux process start ticks, and run ID for diagnosis. A second runner
cannot enter while the lease is held. The receipt remains the approval gate and
is published only after every model artifact and semantic check has passed.

The state binds provider, role, model configuration, repository, mission, base,
HEAD, diff, registry, runner, invocation code, schemas, qualification receipt,
and input plan. A changed identity invalidates the previous state and starts a
new run. A committed stage contains its canonical artifact path, artifact and
output SHA256, prompt input SHA256, validation result, and completion time.
On resume, the runner checks the full committed prefix and each artifact hash,
then revalidates the artifact against the current stage input before reuse.

The commit order is: invoke, validate, atomically write and fsync artifact,
atomically replace and fsync state. A crash before state commit leaves an
uncommitted artifact, which is discarded before the stage is invoked again.
The model call can therefore occur more than once for an uncommitted stage.
Committed stages are reused once logically and never invoked again. No later
stage can start until the previous stage is durably committed. Receipt writing
uses the same commit-last rule and accepts only identical bytes after a crash
between receipt publication and state update.

Cancellation and transient transport/timeout failures are marked resumable in
the failure artifact; invalid model output and other failures are terminal for
automatic retry. A failure artifact is never an approval receipt. Resuming a
terminal failure requires a deliberate new invocation of the runner, which still
reuses only valid committed stages and reexecutes the incomplete stage.

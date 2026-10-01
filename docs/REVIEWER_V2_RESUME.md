# Reviewer V2 durable resume

Private, fsynced artifacts and an `flock` lease protect each review run. State
binds model, repository, HEAD, diff, code, schema, qualification, and inputs.
Resume verifies completed artifact and prompt hashes. Each stage invokes,
validates, writes its artifact, then commits state; the receipt is last.
Uncommitted model calls may repeat. Only explicit transient failures permit
one bounded stage retry. Failure artifacts never approve a review.

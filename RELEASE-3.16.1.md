# Agent 3.16.1 — serialize durable usage sampling

Fix periodic usage capture racing with the minute forwarding-DNS seal (also
run on core-only nodes). Two RPC reads could finish out of order. The older
cumulative reading was then interpreted as a core counter reset, producing a
full historical counter as a new billable delta.

All periodic read-to-commit operations now use the existing core lifecycle
mutex, as do forwarding seals and snapshot activation. This also prevents a
sample spanning an actual core restart. Lock ordering remains core lifecycle
then reset metadata, then the durable store transaction. Counter reset and
forwarding-scope semantics, sequence/generation, ACKs and billing multipliers
are unchanged; no databases or queues are reset.

Regression test forces the newer sample to commit first in the broken code:
baseline 90, readings 100 and 110 formerly bill 120 instead of 20. Covers two
periodic callers and periodic capture versus a forwarding seal. Activation
also waits for the lifecycle fence. Existing restart, forwarding, queue-limit,
audit and durable delivery regressions remain required.

Release version, Docker defaults and immutable image tag are all 3.16.1.
The bundled sing-box remains 1.14.0. No panel/frontend feature changes.

Historical usage is not silently rewritten by an Agent update. Corrections
require an explicit source-snapshot manifest, a private database backup,
underflow/precondition checks, an idempotency record, and a single transaction.
Source snapshots and access audit records must remain intact.

Local verification (2026-10-19): deterministic regression fails on 3.16.0
with 120 billed bytes in both schedules and passes after the fix with 20.
All packages pass `go test -race ./...` and `go vet ./...` in a cached
Go 1.26 container. Patched sing-box Snell/accounting and native audit stream
integration tests pass in an isolated, network-disabled container as well.

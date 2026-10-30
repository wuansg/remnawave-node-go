# Agent 3.16.2 — bound usage sampling and keep restart markers

Usage capture holds the core lifecycle mutex while it reads sing-box stats.
Those RPCs had no deadline, so a hung stats API blocked Start, restarts and
forwarding syncs indefinitely. Counter collection now has a 5 second timeout.

A failed stats query used to be swallowed as an empty list. The capture then
consumed the core restart marker without sampling user counters, and the next
sample billed only current minus the pre-restart baseline. Core counters are
now dropped as a whole for that sample and the restart marker is kept for the
next complete one. Forwarding counters are still sealed, so forwarding syncs
keep working while the core stats API is unavailable.

Snapshot activation refuses to store a baseline without core counters, which
would otherwise replay the core's lifetime totals on the first capture.

Regression tests: a hung stats RPC releases the lifecycle lock; a failed sample
after a restart keeps the marker and the next sample bills 1500 instead of 500;
activation with failing core stats returns ErrCoreUnavailable. The latter two
fail on 3.16.1.

Release version, Docker defaults and immutable image tag are all 3.16.2.
The bundled sing-box remains 1.14.0. No panel/frontend changes.

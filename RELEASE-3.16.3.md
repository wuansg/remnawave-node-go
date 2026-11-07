# Agent 3.16.3 — seal core usage before stop/restart and preserve nftables blocks

Restarting or stopping `sing-box` (via `Start`, user add/remove updates,
rollback, or `Stop`) now seals accumulated core usage counters before stopping
the running process and consistently sets the core restart marker so the first
post-restart sample treats restarted counters as fresh traffic. While the core
is stopped, forwarding-only samples no longer consume the core restart marker.

`BlockIPs`, `UnblockIPs`, and `RecreateTables` now serialize on `coreMu`.
Recreating the `remnanode` nftables table (during plugin sync, plugin removal,
rollback, or manual table recreation) replays active `temporary-blocked-ip` /
`temporary-blocked-ip6` elements with their remaining timeouts and prunes
expired entries; `RecreateTables` also re-syncs active plugin filter sets.

# Remnawave Node Go parity plan

Baseline: Go `5810d6e`; reference implementation `../node` at `45052dd`.

Completion rule: an item is checked only after its implementation and relevant tests pass. Test evidence is recorded beside the item.

- [x] Runtime lifecycle and concurrency safety — verified with `GOCACHE=/tmp/remnawave-go-cache go test -race ./...` and `go vet ./...`
  - Serialize core-mutating operations.
  - Honor `DISABLE_HASHED_SET_CHECK`.
  - Include core type and live process state in restart decisions.
  - Commit running-core/hash state only after a successful start.
  - Stop polling core version binaries every five seconds.
- [x] Native core API clients — verified with native Xray protobuf clients, local mTLS configuration, and `go test -race ./...`
  - Add injectable Stats, Handler, and Routing interfaces.
  - Use Xray gRPC with local mTLS and enable Handler/Stats/Routing services.
  - Enable Sing-box V2Ray stats while retaining Clash connection APIs.
- [x] Real core statistics — verified with aggregation/reset unit tests, `go test -race ./...`, and `go vet ./...`
  - Implement user/inbound/outbound/combined traffic and reset semantics.
  - Return core runtime statistics from `get-system-stats`.
  - Preserve active-connection based Sing-box online/IP reporting.
- [x] Correct user management — verified with multi-inbound regression coverage and `go test -race ./...`
  - Fix multi-inbound single-user updates.
  - Use dynamic Xray Handler operations without restarting Xray.
  - Keep one-restart-per-request Sing-box updates and AnyTLS/Hysteria2/TUIC support.
  - Drop removed users' active connections and propagate failures.
- [x] Vision and plugin parity — verified with routing-tag and torrent configuration tests, IPv4/IPv6 nftables generation, `go test -race ./...`, and `go vet ./...`
  - Apply Vision block/unblock through Xray RoutingService.
  - Generate complete torrent-blocker routing/outbound/webhook configuration.
  - Apply `includeRuleTags`, validate webhook reports, and propagate nftables errors.
  - Support IPv4/IPv6 and detect required network capability.
- [x] HTTP contract compatibility — verified with validation/compression middleware tests and `go test -race ./...`
  - Validate requests against the Node contract.
  - Align response/error/healthcheck semantics.
  - Enforce a 1 GiB decompressed body limit and add compression/security/timeouts.
- [x] Deployment and documentation — verified by an amd64 Podman image build and bundled core smoke tests
  - Add `NET_ADMIN` and `nofile` deployment settings.
  - Make Docker builds architecture-aware and restore custom-core support.
  - Update README and add container integration/smoke coverage.
- [x] Final verification
  - `GOMODCACHE=/tmp/remnawave-gomodcache GOCACHE=/tmp/remnawave-go-cache go test -race ./...`
  - `GOMODCACHE=/tmp/remnawave-gomodcache GOCACHE=/tmp/remnawave-go-cache go vet ./...`
  - amd64 image `remnawave-node-go:local` built successfully.
  - Xray `26.3.27`, Sing-box `1.13.13`, and Go entry-binary startup smoke tests passed.

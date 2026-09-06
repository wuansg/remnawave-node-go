# Remnawave Node Go

Go implementation of Remnawave Node with a sing-box-only runtime.

The public HTTPS API requires mTLS and RS256 JWT authentication. Sing-box exposes its statistics and authenticated Clash APIs only on loopback.

## Features

- Parses the existing `SECRET_KEY` base64 JSON payload.
- Starts HTTPS with node certificate, node key, CA, and required client certificates.
- Verifies `Authorization: Bearer ...` JWTs signed with the payload `jwtPublicKey` using `RS256`.
- Implements the Remnawave routes under `/node/...`, including temporary legacy core-route aliases.
- Provides sing-box traffic, system, online-user, and online-IP statistics.
- Supports restart-based sing-box users, including AnyTLS, Hysteria2, and TUIC.
- Supports connection dropping, ingress/egress filters, forwarding rules, and IPv4/IPv6 nftables sets.
- Accepts plain and zstd-compressed request bodies and gzip-compresses responses.

## Run

```sh
NODE_PORT=2222 \
SECRET_KEY=... \
INTERNAL_SOCKET_PATH=/run/remnawave/internal.sock \
INTERNAL_REST_TOKEN=... \
go run ./cmd/remnawave-node-go
```

For container deployment, use the supplied Compose file. Network plugins require `CAP_NET_ADMIN`, which the Compose configuration enables.

Run verification with:

```sh
go test -race ./...
go vet ./...
```

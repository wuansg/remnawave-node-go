# Remnawave Node Go

Go implementation of Remnawave Node, compatible with the Remnawave Node 2.7 API and supporting Xray and Sing-box cores.

The public HTTPS API requires mTLS and RS256 JWT authentication. Core-local APIs are bound to loopback; Xray uses ephemeral mTLS credentials and Sing-box exposes V2Ray statistics plus an authenticated Clash API.

## Features

- Parses the existing `SECRET_KEY` base64 JSON payload.
- Starts HTTPS with node certificate, node key, CA, and required client certificates.
- Verifies `Authorization: Bearer ...` JWTs signed with the payload `jwtPublicKey` using `RS256`.
- Implements the existing Remnawave routes under `/node/...`.
- Serves internal xray config and webhook paths on `INTERNAL_SOCKET_PATH`.
- Provides native Xray Stats, Handler, and Routing gRPC clients.
- Provides Xray and Sing-box traffic, system, online-user, and online-IP statistics.
- Supports dynamic Xray users and restart-based Sing-box users, including AnyTLS, Hysteria2, and TUIC.
- Supports Vision routing, connection dropping, torrent blocking, ingress/egress filters, and IPv4/IPv6 nftables sets.
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

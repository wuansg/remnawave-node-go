# Remnawave Node Go

Experimental Go rewrite of Remnawave Node.

This repository is intentionally separate from the current TypeScript/NestJS node. The first milestone keeps the public contract compatible while the xray/sing-box control plane is migrated behind small adapters.

## Implemented

- Parses the existing `SECRET_KEY` base64 JSON payload.
- Starts HTTPS with node certificate, node key, CA, and required client certificates.
- Verifies `Authorization: Bearer ...` JWTs signed with the payload `jwtPublicKey` using `RS256`.
- Registers the existing Remnawave routes under `/node/...`.
- Serves internal xray config and webhook paths on `INTERNAL_SOCKET_PATH`.
- Keeps runtime xray config in memory for `/internal/get-config`.
- Provides a baseline `/node/xray/healthcheck` response.

## Not Implemented Yet

- xray-core gRPC handler and stats operations.
- sing-box stats and process control.
- nftables/plugin behavior.
- supervisord XML-RPC calls beyond adapter scaffolding.

## Run

```sh
NODE_PORT=2222 \
SECRET_KEY=... \
INTERNAL_SOCKET_PATH=/run/remnawave/internal.sock \
INTERNAL_REST_TOKEN=... \
go run ./cmd/remnawave-node-go
```

The local environment used to create this repository did not have Go installed, so build/test verification still needs to run on a machine with a Go toolchain.

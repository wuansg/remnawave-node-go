FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine AS go-build

ARG REMNAWAVE_NODE_VERSION=3.8.0
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-X github.com/remnawave/remnawave-node-go/internal/config.buildVersion=${REMNAWAVE_NODE_VERSION}" \
    -o /out/remnawave-node-go ./cmd/remnawave-node-go


FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS sing-box-build

ARG SING_BOX_VERSION=1.14.0
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY third_party/sing-box-patches /patches

RUN apk add --no-cache git patch \
    && git clone --depth 1 --branch v${SING_BOX_VERSION} https://github.com/SagerNet/sing-box.git . \
    && patch -p1 < /patches/0001-expose-user-in-clash-connections.patch \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build \
        -tags "with_v2ray_api,with_clash_api,with_quic" \
        -ldflags "-X github.com/sagernet/sing-box/constant.Version=${SING_BOX_VERSION}" \
        -o /usr/local/bin/sing-box ./cmd/sing-box


FROM --platform=$BUILDPLATFORM alpine:3.22 AS geocheck

ARG GEOCHECK_VERSION=0.3.0
ARG GEOCHECK_RELEASE_URL=https://github.com/remnawave/geocheck/releases/download
ARG TARGETARCH

RUN apk add --no-cache curl \
    && cd /tmp \
    && ARCHIVE="geocheck_linux_${TARGETARCH}.tar.gz" \
    && curl -fsSL -O "${GEOCHECK_RELEASE_URL}/v${GEOCHECK_VERSION}/${ARCHIVE}" \
    && curl -fsSL -O "${GEOCHECK_RELEASE_URL}/v${GEOCHECK_VERSION}/checksums.txt" \
    && grep "  ${ARCHIVE}$" checksums.txt | sha256sum -c - \
    && tar -xzf "${ARCHIVE}" geocheck \
    && install -m 0755 geocheck /usr/local/bin/geocheck


FROM alpine:3.22

ARG REMNAWAVE_NODE_VERSION=3.8.0
ARG SING_BOX_VERSION=1.14.0

LABEL org.opencontainers.image.title="Remnawave Node Go"
LABEL org.opencontainers.image.description="Go-based Remnawave Node with sing-box support"
LABEL org.opencontainers.image.url="https://github.com/remnawave/remnawave-node-go"
LABEL org.opencontainers.image.source="https://github.com/remnawave/remnawave-node-go"
LABEL org.opencontainers.image.vendor="Remnawave"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.documentation="https://docs.rw"
LABEL org.opencontainers.image.version="${REMNAWAVE_NODE_VERSION}"
LABEL org.opencontainers.image.sing-box.version="${SING_BOX_VERSION}"

RUN apk add --no-cache supervisor curl ca-certificates iproute2 nftables \
	&& mkdir -p /var/log/supervisor /run/remnawave /var/lib/remnanode

COPY --from=go-build /out/remnawave-node-go /usr/local/bin/remnawave-node-go
COPY --from=sing-box-build /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=geocheck /usr/local/bin/geocheck /usr/local/bin/geocheck

RUN printf '%s\n' '{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}' > /tmp/sing-box-smoke.json \
	&& /usr/local/bin/sing-box version | grep -F "sing-box version ${SING_BOX_VERSION}" \
	&& /usr/local/bin/sing-box check -c /tmp/sing-box-smoke.json \
	&& /usr/local/bin/sing-box schema > /dev/null \
	&& rm /tmp/sing-box-smoke.json

COPY supervisord.conf /etc/supervisord.conf
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
	&& printf '#!/bin/sh\ntail -n +1 -f /var/log/supervisor/sing-box.out.log\n' > /usr/local/bin/sblogs \
	&& printf '#!/bin/sh\ntail -n +1 -f /var/log/supervisor/sing-box.err.log\n' > /usr/local/bin/sberrors \
	&& chmod +x /usr/local/bin/sblogs /usr/local/bin/sberrors

ENV NODE_PORT=2222
ENV SING_BOX_API_PORT=61001
ENV SING_BOX_V2RAY_API_PORT=61002
ENV SING_BOX_VERSION=${SING_BOX_VERSION}
ENV SING_BOX_CONFIG_PATH=/run/remnawave/sing-box.json
ENV SING_BOX_BINARY_PATH=/usr/local/bin/sing-box
ENV SING_BOX_LAST_GOOD_CONFIG_PATH=/var/lib/remnanode/sing-box.last-good.json
ENV USAGE_SNAPSHOT_DB_PATH=/var/lib/remnanode/stats.db
ENV FORWARDING_STATE_PATH=/var/lib/remnanode/forwarding.json

VOLUME ["/var/lib/remnanode"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/remnawave-node-go"]

FROM golang:1.26.4-alpine AS go-build

ARG REMNAWAVE_NODE_VERSION=2.7.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-X github.com/remnawave/remnawave-node-go/internal/config.buildVersion=${REMNAWAVE_NODE_VERSION}" \
    -o /out/remnawave-node-go ./cmd/remnawave-node-go


FROM alpine:3.22 AS xray-build

ARG XRAY_CORE_VERSION=v26.3.27
ARG UPSTREAM_REPO=XTLS
ARG XRAY_CORE_INSTALL_SCRIPT=https://raw.githubusercontent.com/remnawave/scripts/main/scripts/install-xray.sh

RUN apk add --no-cache curl unzip \
    && curl -L ${XRAY_CORE_INSTALL_SCRIPT} | sh -s -- ${XRAY_CORE_VERSION} ${UPSTREAM_REPO}


FROM golang:1.25-alpine AS sing-box-build

ARG SING_BOX_VERSION=v1.13.13

WORKDIR /src
COPY third_party/sing-box-patches /patches

RUN apk add --no-cache git build-base patch \
    && git clone --depth 1 --branch ${SING_BOX_VERSION} https://github.com/SagerNet/sing-box.git . \
    && patch -p1 < /patches/0001-expose-user-in-clash-connections.patch \
    && go build -tags "with_v2ray_api,with_clash_api,with_quic" -o /usr/local/bin/sing-box ./cmd/sing-box


FROM alpine:3.22

LABEL org.opencontainers.image.title="Remnawave Node Go"
LABEL org.opencontainers.image.description="Go-based Remnawave Node with Xray and Sing-box support"
LABEL org.opencontainers.image.url="https://github.com/remnawave/remnawave-node-go"
LABEL org.opencontainers.image.source="https://github.com/remnawave/remnawave-node-go"
LABEL org.opencontainers.image.vendor="Remnawave"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.documentation="https://docs.rw"

RUN apk add --no-cache supervisor curl ca-certificates iproute2 nftables \
    && mkdir -p /var/log/supervisor /run/remnawave

COPY --from=go-build /out/remnawave-node-go /usr/local/bin/remnawave-node-go
COPY --from=xray-build /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray-build /usr/local/share/xray/geoip.dat /usr/local/share/xray/geoip.dat
COPY --from=xray-build /usr/local/share/xray/geosite.dat /usr/local/share/xray/geosite.dat
COPY --from=sing-box-build /usr/local/bin/sing-box /usr/local/bin/sing-box

COPY supervisord.conf /etc/supervisord.conf
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
	&& ln -s /usr/local/bin/xray /usr/local/bin/rw-core \
	&& printf '#!/bin/sh\ntail -n +1 -f /var/log/supervisor/xray.out.log\n' > /usr/local/bin/xlogs \
	&& printf '#!/bin/sh\ntail -n +1 -f /var/log/supervisor/xray.err.log\n' > /usr/local/bin/xerrors \
	&& printf '#!/bin/sh\ntail -n +1 -f /var/log/supervisor/sing-box.out.log\n' > /usr/local/bin/sblogs \
	&& printf '#!/bin/sh\ntail -n +1 -f /var/log/supervisor/sing-box.err.log\n' > /usr/local/bin/sberrors \
	&& chmod +x /usr/local/bin/xlogs /usr/local/bin/xerrors /usr/local/bin/sblogs /usr/local/bin/sberrors

ENV NODE_PORT=2222
ENV XTLS_API_PORT=61000
ENV SING_BOX_API_PORT=61001
ENV XRAY_CONFIG_PATH=/run/remnawave/xray.json
ENV SING_BOX_CONFIG_PATH=/run/remnawave/sing-box.json

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/remnawave-node-go"]

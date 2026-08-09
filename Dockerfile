FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine AS go-build

ARG REMNAWAVE_NODE_VERSION=3.0.0
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-X github.com/remnawave/remnawave-node-go/internal/config.buildVersion=${REMNAWAVE_NODE_VERSION}" \
    -o /out/remnawave-node-go ./cmd/remnawave-node-go


FROM --platform=$BUILDPLATFORM alpine:3.22 AS xray-build

ARG XRAY_CORE_VERSION=v26.3.27
ARG UPSTREAM_REPO=XTLS
ARG TARGETARCH

RUN apk add --no-cache curl unzip \
    && case "${TARGETARCH}" in \
        amd64) XRAY_ARCH=64 ;; \
        arm64) XRAY_ARCH=arm64-v8a ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && if [ "${XRAY_CORE_VERSION}" = "latest" ]; then \
        XRAY_URL="https://github.com/${UPSTREAM_REPO}/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip"; \
    else \
        XRAY_URL="https://github.com/${UPSTREAM_REPO}/Xray-core/releases/download/${XRAY_CORE_VERSION}/Xray-linux-${XRAY_ARCH}.zip"; \
    fi \
    && curl -fL "${XRAY_URL}" -o /tmp/xray.zip \
    && unzip -q /tmp/xray.zip -d /tmp/xray \
    && install -m 755 /tmp/xray/xray /usr/local/bin/xray \
    && install -d /usr/local/share/xray \
    && install -m 644 /tmp/xray/geoip.dat /usr/local/share/xray/geoip.dat \
    && install -m 644 /tmp/xray/geosite.dat /usr/local/share/xray/geosite.dat


FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS sing-box-build

ARG SING_BOX_VERSION=1.13.16
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


FROM alpine:3.22

ARG SING_BOX_VERSION=1.13.16

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
ENV SING_BOX_V2RAY_API_PORT=61002
ENV SING_BOX_VERSION=${SING_BOX_VERSION}
ENV XRAY_CONFIG_PATH=/run/remnawave/xray.json
ENV SING_BOX_CONFIG_PATH=/run/remnawave/sing-box.json

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/remnawave-node-go"]

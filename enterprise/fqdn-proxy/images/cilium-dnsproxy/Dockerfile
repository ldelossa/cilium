# syntax=docker/dockerfile:1.7@sha256:dbbd5e059e8a07ff7ea6233b213b36aa516b4c53c645f1817a4dd18b83cbea56

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch

# This is for copying tar command.
FROM --platform=${BUILDPLATFORM} docker.io/library/busybox:1.36.1-musl@sha256:84fbdf15839802266b3ff1420959c2efb8d10ab1f8122c31f714f977969cc801 as busybox

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} docker.io/library/golang:1.22.1@sha256:34ce21a9696a017249614876638ea37ceca13cdd88f582caad06f87a8aa45bf3 as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP
ARG LOCKDEBUG
ARG RACE

WORKDIR /go/src/github.com/isovalent/fqdn-proxy
RUN --mount=type=bind,readwrite,target=/go/src/github.com/isovalent/fqdn-proxy --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} LOCKDEBUG=${LOCKDEBUG} \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv dnsproxy /out/${TARGETOS}/${TARGETARCH}/usr/bin

FROM --platform=${BUILDPLATFORM} golang:1.22.1@sha256:34ce21a9696a017249614876638ea37ceca13cdd88f582caad06f87a8aa45bf3 as gops
WORKDIR /go/src/github.com/isovalent/fqdn-proxy/images/cilium-dnsproxy
RUN --mount=type=bind,readwrite,target=/go/src/github.com/isovalent/fqdn-proxy/images/cilium-dnsproxy --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./images/cilium-dnsproxy/build-gops.sh

FROM ${BASE_IMAGE}
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
# kubectl cp uses tar.
COPY --from=busybox /bin/sh /bin/sh
COPY --from=busybox /bin/tar /bin/tar
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/dnsproxy /usr/bin/dnsproxy
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /usr/bin/gops
WORKDIR /
ENV GOPS_CONFIG_DIR=/
CMD ["/usr/bin/dnsproxy"]

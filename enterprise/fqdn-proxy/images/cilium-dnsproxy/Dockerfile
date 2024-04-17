# syntax=docker/dockerfile:1.7@sha256:dbbd5e059e8a07ff7ea6233b213b36aa516b4c53c645f1817a4dd18b83cbea56

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=docker.io/library/golang:1.22.1@sha256:34ce21a9696a017249614876638ea37ceca13cdd88f582caad06f87a8aa45bf3
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:819a4f1e57eaacb6aabfc6a1a39d11d4fd794a88@sha256:24781dc80f2be2d8fd66b0ce1405e1f117a3a0ef388758b1ede7831778e3a4f7

# This is for copying tar command.
FROM --platform=${BUILDPLATFORM} docker.io/library/busybox:1.36.1-musl@sha256:84fbdf15839802266b3ff1420959c2efb8d10ab1f8122c31f714f977969cc801 as busybox

#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the date on which the compatible build image
# was pushed.  If a new version of the build image is needed, it needs
# to be tagged with a new date and this file must be changed
# accordingly.  Keeping the old images available will allow older
# versions to be built while allowing the new versions to make changes
# that are not backwards compatible.
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP
ARG NOOPT
ARG LOCKDEBUG
ARG RACE
ARG V

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} V=${V} \
    DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} -C enterprise/fqdn-proxy all install

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-gops.sh

FROM ${BASE_IMAGE} as release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
# kubectl cp uses tar.
COPY --from=busybox /bin/sh /bin/sh
COPY --from=busybox /bin/tar /bin/tar
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH}/usr/bin/dnsproxy /usr/bin/dnsproxy
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /usr/bin/gops
WORKDIR /
ENV GOPS_CONFIG_DIR=/
CMD ["/usr/bin/dnsproxy"]

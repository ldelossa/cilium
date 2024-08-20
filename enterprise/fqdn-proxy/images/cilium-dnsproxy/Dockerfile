# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=docker.io/library/golang:1.23.0@sha256:613a108a4a4b1dfb6923305db791a19d088f77632317cfc3446825c54fb862cd
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:874230be6e22cf9ff9c4515097b5aee80b76ee8d@sha256:940c75b1a94de9d5f529ef40fcea3f71fef592f8744984eae93862852f4870d9

# This is for copying tar command.
FROM --platform=${BUILDPLATFORM} docker.io/library/busybox:1.36.1-musl@sha256:ede585a46e84850ffa6e3331c53ac571fe71d9b1ba9299f7925b052985db3e7f AS busybox

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
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS builder

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
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-gops.sh

FROM ${BASE_IMAGE} AS release
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

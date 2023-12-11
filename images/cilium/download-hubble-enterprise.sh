#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases
hubble_version="v0.12.3-cee.1"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.12.3-cee.1
hubble_sha256[amd64]="7180beae7ab1c871f9c2c034118bea65f01838a222a2fd52feac26e3c4c499f4"
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.12.3-cee.1
hubble_sha256[arm64]="922d081f80844b222725fa41ea31cc3ee96fddb2815cb4c858ce2fb561dfc7a1"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/isovalent/hubble-releases/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble

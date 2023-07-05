#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases
hubble_version="v0.11.6-cee.2"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.11.6-cee.2
hubble_sha256[amd64]="b1ae83cfd47503b647d05578292ac429d71d4cf22598b69ffe9a27e50a5e4d55"
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.11.6-cee.2
hubble_sha256[arm64]="09a2820fac5f8441ddac7374b6ed3c03a6a45ce413715d4f211c20867f94695e"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/isovalent/hubble-releases/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble

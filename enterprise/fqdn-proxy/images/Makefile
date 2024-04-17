# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRIES ?= docker.io/cilium
# quay.io is not enabled, see https://github.com/cilium/image-tools/issues/11
# REGISTRIES ?= docker.io/cilium quay.io/cilium

PUSH ?= false

OUTPUT := "type=image"
ifeq ($(PUSH),true)
OUTPUT := "type=registry,push=true"
endif

PLATFORMS=linux/amd64,linux/arm64

SCRIPTS=../../../images/scripts

all-images: cilium-dnsproxy-image

lint:
	$(SCRIPTS)/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --platform $(PLATFORMS) --buildkitd-flags '--debug' > $@

update-runtime-image:
	$(SCRIPTS)/update-cilium-runtime-image.sh

check-runtime-image:
	CHECK=true $(SCRIPTS)/update-cilium-runtime-image.sh

update-builder-image:
	$(SCRIPTS)/update-cilium-builder-image.sh

check-builder-image:
	CHECK=true $(SCRIPTS)/update-cilium-builder-image.sh

cilium-dnsproxy-image: .buildx_builder
	ROOT_CONTEXT=true $(SCRIPTS)/build-image.sh cilium-dnsproxy enterprise/fqdn-proxy/images/cilium-dnsproxy $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

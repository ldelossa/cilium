# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../../Makefile.defs

DNSPROXY_CHARTS := $(ROOT_DIR)/$(RELATIVE_DIR)
CHART_FILE := "$(DNSPROXY_CHARTS)/Chart.yaml"

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
DNSPROXY_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)

all: update-chart

update-chart: $(ROOT_DIR)/VERSION # Update chart versions to point to the current version.
	$(ECHO_GEN)enterprise/fqdn-proxy/Chart.yaml
	$(QUIET)grep -lR -e 'version:' -e 'appVersion:' $(DNSPROXY_CHARTS)/ \
		| xargs -L 1 $(SED) -i -e 's/'$(DNSPROXY_CHART_REGEX)'/\1 '$(VERSION)'/g'

.PHONY: all update-chart

include ../Makefile.defs

.PHONY: enterprise-proto
enterprise-proto:
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C plugins/hubble-flow-aggregation/api/aggregation
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C api/extensions

generate-enterprise-api: api/v1/openapi.yaml ## Generate enterprise client, model and server code from openapi spec.
	-$(QUIET)$(SWAGGER) generate server -s server -a restapi \
		-t enterprise/api/v1 \
		-f enterprise/api/v1/openapi.yaml \
		--default-scheme=unix \
		-C api/v1/cilium-server.yml \
		-r enterprise/api/v1/copyright-header.txt
	-$(QUIET)$(SWAGGER) generate client -a restapi \
		-t enterprise/api/v1 \
		-f enterprise/api/v1/openapi.yaml \
		-r enterprise/api/v1/copyright-header.txt
	@# sort goimports automatically
	-$(QUIET)$(GO) run golang.org/x/tools/cmd/goimports -w ./api/v1/
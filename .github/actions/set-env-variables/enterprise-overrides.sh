#!/usr/bin/env bash
#
# Use this script to override environment variables that get set in the
# upstream set-env-variables composite action.

set -ex

echo "QUAY_ORGANIZATION=isovalent" >> "$GITHUB_ENV"
echo "QUAY_ORGANIZATION_DEV=isovalent-dev" >> "$GITHUB_ENV"
echo "CILIUM_HELM_REPO_NAME=isovalent" >> "$GITHUB_ENV"
echo "CILIUM_HELM_REPO_URL=https://helm.isovalent.com" >> "$GITHUB_ENV"
echo "CILIUM_CLI_REPO=isovalent/cilium-cli-releases" >> "$GITHUB_ENV"
echo "CILIUM_OSS_HELM_REPO_NAME=cilium" >> $GITHUB_ENV
echo "CILIUM_OSS_HELM_REPO_URL=https://helm.cilium.io" >> $GITHUB_ENV
echo "CILIUM_OSS_CLI_REPO=cilium/cilium-cli" >> $GITHUB_ENV

echo "QUAY_CHARTS_ORGANIZATION_DEV=isovalent-charts-dev" >> "$GITHUB_ENV"
echo "QUAY_OSS_CHARTS_ORGANIZATION_DEV=cilium-charts-dev" >> $GITHUB_ENV
echo "BRANCH_SUFFIX=-ce" >> "$GITHUB_ENV"
echo "TAG_SUFFIX=-cee.1" >> "$GITHUB_ENV"
echo "EGRESS_GATEWAY_HELM_VALUES=--helm-set=egressGateway.enabled=true --helm-set=enterprise.egressGatewayHA.enabled=true" >> "$GITHUB_ENV"

echo "CILIUM_CLI_RELEASE_REPO=isovalent/cilium-cli-releases" >> "$GITHUB_ENV"
# renovate: datasource=github-releases depName=isovalent/cilium-cli-releases
CILIUM_CLI_VERSION="v0.16.3-cee.1"
echo "CILIUM_CLI_VERSION=$CILIUM_CLI_VERSION" >> "$GITHUB_ENV"
echo "CILIUM_CLI_IMAGE_REPO=quay.io/isovalent-dev/cilium-cli-ci" >> $GITHUB_ENV
echo "CILIUM_CLI_SKIP_BUILD=false" >> $GITHUB_ENV

echo "PUSH_TO_DOCKER_HUB=false" >> "$GITHUB_ENV"

echo "GCP_PERF_RESULTS_BUCKET=gs://cilium-scale-results-cee" >> "$GITHUB_ENV"

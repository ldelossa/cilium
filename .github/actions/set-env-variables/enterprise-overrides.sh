#!/usr/bin/env bash
#
# Use this script to override environment variables that get set in the
# upstream set-env-variables composite action.

set -ex

echo "CILIUM_CLI_RELEASE_REPO=isovalent/cilium-cli-releases" >> "$GITHUB_ENV"
# renovate: datasource=github-releases depName=isovalent/cilium-cli-releases
CILIUM_CLI_VERSION="v0.15.19-cee.1"
echo "CILIUM_CLI_VERSION=$CILIUM_CLI_VERSION" >> "$GITHUB_ENV"

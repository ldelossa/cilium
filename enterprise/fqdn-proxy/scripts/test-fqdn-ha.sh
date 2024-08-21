#!/usr/bin/env bash

set -eu -o pipefail

kubectl exec -n cilium-test-1 deploy/client -- nslookup cilium.io
kubectl exec -n cilium-test-1 deploy/client -- curl --max-time 10 cilium.io

kubectl exec -n cilium-test-1 deploy/client -- nslookup google.com

if kubectl exec -n cilium-test-1 deploy/client -- curl --max-time 10 google.com ; then
	echo "google.com reached despite being blocked by fqdn policy"
	exit 1
fi

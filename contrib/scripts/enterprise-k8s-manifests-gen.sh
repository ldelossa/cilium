#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

##@ API targets
# Set CRD_OPTIONS if not already set
CRD_OPTIONS="${CRD_OPTIONS:-"crd:crdVersions=v1"}"

# Set CRD_PATHS using the current working directory
CRD_PATHS="${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/v1;${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/v1alpha1;"

# Set CRDS_ISOVALENT_PATHS using the current working directory
CRDS_ISOVALENT_PATHS="${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1 ${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1alpha1"

# Set CRDS_ISOVALENT_V1 with the list of CRDs for v1alpha1
CRDS_ISOVALENT_V1="isovalentegressgatewaypolicies"

# Set CRDS_ISOVALENT_V1ALPHA1 with the list of CRDs for v1alpha1
CRDS_ISOVALENT_V1ALPHA1="isovalentfqdngroups \
                         isovalentsrv6sidmanagers \
                         isovalentsrv6locatorpools \
                         isovalentsrv6egresspolicies \
                         isovalentvrfs \
                         isovalentpodnetworks \
                         isovalentmulticastgroups \
                         isovalentmulticastnodes \
                         isovalentmeshendpoints \
                         isovalentbfdprofiles \
                         isovalentbfdnodeconfigs \
                         isovalentbfdnodeconfigoverrides \
                         isovalentbgpclusterconfigs \
                         isovalentbgppeerconfigs \
                         isovalentbgpadvertisements \
                         isovalentbgpnodeconfigs \
                         isovalentbgpnodeconfigoverrides \
                         isovalentbgpvrfconfigs"

TMPDIR=$(mktemp -d -t cilium.tmpXXXXXXXX)
go run sigs.k8s.io/controller-tools/cmd/controller-gen ${CRD_OPTIONS} paths="${CRD_PATHS}" output:crd:artifacts:config="${TMPDIR}"
go run ${SCRIPT_ROOT}/../../tools/crdcheck "${TMPDIR}"

# Clean up old CRD state and start with a blank state.
for path in ${CRDS_ISOVALENT_PATHS}; do
  rm -rf "${path}" && mkdir "${path}"
done

for file in ${CRDS_ISOVALENT_V1}; do
  mv "${TMPDIR}/isovalent.com_${file}.yaml" "${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1/${file}.yaml";
done

for file in ${CRDS_ISOVALENT_V1ALPHA1}; do
  mv "${TMPDIR}/isovalent.com_${file}.yaml" "${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1alpha1/${file}.yaml";
done

rm -rf "${TMPDIR}"

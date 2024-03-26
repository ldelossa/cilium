// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	isovalent_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

const (
	k8sAPIGroupIsovalentEgressGatewayPolicyV1 = "isovalent/v1::IsovalentEgressGatewayPolicy"
	k8sAPIGroupIsovalentMeshEndpointV1Alpha1  = "isovalent/v1alpha1::IsovalentMeshEndpoint"
)

var isovalentResourceToGroupMapping = map[string]watcherInfo{
	synced.CRDResourceName(isovalent_v1.IEGPName):              {start, k8sAPIGroupIsovalentEgressGatewayPolicyV1},
	synced.CRDResourceName(v1alpha1.IsovalentMeshEndpointName): {start, k8sAPIGroupIsovalentMeshEndpointV1Alpha1},
}

func init() {
	for crdName, watcher := range isovalentResourceToGroupMapping {
		ciliumResourceToGroupMapping[crdName] = watcher
	}
}

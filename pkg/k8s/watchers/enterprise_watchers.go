// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	isovalent_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

var isovalentResourceToGroupMapping = map[string]watcherInfo{
	synced.CRDResourceName(isovalent_v1.IEGPName): {start, k8sAPIGroupIsovalentEgressGatewayPolicyV1},
}

func init() {
	for crdName, watcher := range isovalentResourceToGroupMapping {
		ciliumResourceToGroupMapping[crdName] = watcher
	}
}

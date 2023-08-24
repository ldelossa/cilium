// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	isovalent_api_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/option"
)

// AllIsovalentCRDResourceNames returns a list of all Isovalent CRD resource
// names.
func AllIsovalentCRDResourceNames() []string {
	result := []string{
		CRDResourceName(v1alpha1.IFGName),
		CRDResourceName(v1alpha1.SRv6SIDManagerName),
		CRDResourceName(v1alpha1.SRv6LocatorPoolName),
	}

	if option.Config.EnableIPv4EgressGateway {
		result = append(result, CRDResourceName(isovalent_api_v1.IEGPName))
	}

	return result
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	netutils "k8s.io/utils/net"

	"github.com/cilium/cilium/pkg/ip"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// VRF is the internal representation of CiliumSRv6VRF.
type VRF struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	// Those two fields are exposed to the BGP manager can deduce which BGP
	// route should be installed in which VRF.
	VRFID uint32
	// The route target informing the BGP manager which VPNv4 advertisements
	// should be imported.
	ImportRouteTarget string
	// The route target we will include in the advertisement of the local node's
	// PodCIDR networks.
	ExportRouteTarget string
	// The allocated SID (IPv6 Addr) used to locate the advertised VPN network.
	// This is a node local value only used if ExportRouteTarget is defined.
	AllocatedSID net.IP

	rules []VRFRule
}

// keysFromEndpoints will iterate over this VRF's rule set, searching for
// any matching endpoints within the `endpoints` argument.
//
// if a provided endpoint matches a rule a srv6map.VRFKey will be created for
// each of the endpoint's IPv6 addresses and appended to the returned slice.
func (v *VRF) keysFromEndpoints(endpoints map[endpointID]*endpointMetadata) []srv6map.VRFKey {
	keys := []srv6map.VRFKey{}
	for _, rule := range v.rules {
		for _, endpoint := range endpoints {
			if !rule.selectsEndpoint(endpoint) {
				continue
			}
			for _, eIP := range endpoint.ips {
				for _, dstCIDR := range rule.dstCIDRs {
					if ip.IsIPv6(eIP) != netutils.IsIPv6CIDR(dstCIDR) {
						// Endpoints can only connect to IPv6 destinations
						// with their IPv6 address.
						continue
					}
					keys = append(keys, srv6map.VRFKey{
						SourceIP: &eIP,
						DestCIDR: dstCIDR,
					})
				}
			}
		}
	}
	return keys
}

// VRFRule is the internal representation of rules from CiliumSRv6VRF.
type VRFRule struct {
	endpointSelectors []api.EndpointSelector
	dstCIDRs          []*net.IPNet
}

// vrfID includes policy name and namespace
type vrfID = types.NamespacedName

// selectsEndpoint determines if the given endpoint is selected by the VRFRule
// based on matching labels of policy and endpoint.
func (rule *VRFRule) selectsEndpoint(endpoint *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpoint.labels)
	for _, selector := range rule.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

func ParseVRF(csrvrf *v2alpha1.CiliumSRv6VRF) (*VRF, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []*net.IPNet
	var rules []VRFRule

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}
	name := csrvrf.ObjectMeta.Name

	if name == "" {
		return nil, fmt.Errorf("CiliumEgressSRv6Policy must have a name")
	}

	for _, rule := range csrvrf.Spec.Rules {
		for _, cidrString := range rule.DestinationCIDRs {
			_, cidr, err := net.ParseCIDR(string(cidrString))
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{logfields.CiliumSRv6VRFName: name}).Warn("Error parsing CIDR.")
				return nil, err
			}
			dstCidrList = append(dstCidrList, cidr)
		}

		for _, selector := range rule.Selectors {
			if selector.NamespaceSelector != nil {
				prefixedNsSelector := selector.NamespaceSelector
				matchLabels := map[string]string{}
				// We use our own special label prefix for namespace metadata,
				// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
				for k, v := range selector.NamespaceSelector.MatchLabels {
					matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
				}

				prefixedNsSelector.MatchLabels = matchLabels

				// We use our own special label prefix for namespace metadata,
				// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
				for i, lsr := range selector.NamespaceSelector.MatchExpressions {
					lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
					prefixedNsSelector.MatchExpressions[i] = lsr
				}

				// Empty namespace selector selects all namespaces (i.e., a namespace
				// label exists).
				if len(selector.NamespaceSelector.MatchLabels) == 0 && len(selector.NamespaceSelector.MatchExpressions) == 0 {
					prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
				}

				endpointSelectorList = append(
					endpointSelectorList,
					api.NewESFromK8sLabelSelector("", prefixedNsSelector, selector.PodSelector))
			} else if selector.PodSelector != nil {
				endpointSelectorList = append(
					endpointSelectorList,
					api.NewESFromK8sLabelSelector("", selector.PodSelector))
			} else {
				return nil, fmt.Errorf("CiliumSRv6VRF cannot have both nil namespace selector and nil pod selector")
			}
		}

		rules = append(rules, VRFRule{
			endpointSelectors: endpointSelectorList,
			dstCIDRs:          dstCidrList,
		})
	}

	return &VRF{
		id: types.NamespacedName{
			Name: name,
		},
		VRFID:             csrvrf.Spec.VRFID,
		ImportRouteTarget: csrvrf.Spec.ImportRouteTarget,
		ExportRouteTarget: csrvrf.Spec.ExportRouteTarget,
		rules:             rules,
	}, nil
}

// ParsePolicyConfigID takes a CiliumSRv6VRF CR and returns only the
// config id.
func ParseVRFID(csrvrf *v2alpha1.CiliumSRv6VRF) types.NamespacedName {
	return vrfID{
		Name: csrvrf.Name,
	}
}

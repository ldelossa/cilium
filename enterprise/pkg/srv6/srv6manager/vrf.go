//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package srv6manager

import (
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// VRF is the internal representation of IsovalentVRF.
// +k8s:deepcopy-gen=true
type VRF struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	// Those two fields are exposed to the BGP manager can deduce which BGP
	// route should be installed in which VRF.
	VRFID uint32
	// Deprecated
	ImportRouteTarget string
	// Deprecated
	ExportRouteTarget string

	// SID allocation information
	LocatorPool string
	SIDInfo     *sidmanager.SIDInfo

	rules []VRFRule
}

// getVRFKeysFromMatchingEndpoint will iterate over this VRF's rule set, searching for
// any matching endpoints within the `endpoints` argument.
//
// if a provided endpoint matches a rule a srv6map.VRFKey will be created for
// each of the endpoint's IPv6 addresses and appended to the returned slice.
func (m *Manager) getVRFKeysFromMatchingEndpoint(vrf *VRF) []srv6map.VRFKey {
	logger := m.logger.WithFields(logrus.Fields{
		logfields.VRF: vrf.id,
	})
	keys := []srv6map.VRFKey{}
	for _, rule := range vrf.rules {
		for _, endpoint := range m.cepStore.List() {
			// NOTE: endpoint.Labels is always nil, as labels are not stored in the slim CiliumEndpoint.
			// Because of that, we need to retrieve them based on the endpoint identity.
			// We could use endpoint.Identity.Labels right away, but that would require parsing them,
			// - so we retrieve them from the identityCache.IdentityAllocator instead (getIdentityLabels).
			if endpoint.Identity == nil {
				logger.WithFields(logrus.Fields{logfields.K8sEndpointName: endpoint.Name, logfields.K8sNamespace: endpoint.Namespace}).
					Warning("Endpoint does not have an identity, skipping from VRF matching")
				continue
			}
			labels, err := m.getIdentityLabels(uint32(endpoint.Identity.ID))
			if err != nil {
				logger.WithFields(logrus.Fields{logfields.K8sEndpointName: endpoint.Name, logfields.K8sNamespace: endpoint.Namespace}).
					WithError(err).Warning("Could not get endpoint identity labels, skipping from VRF matching")
				continue
			}
			if !rule.selectsEndpoint(labels.K8sStringMap()) {
				continue
			}
			var ips []netip.Addr
			for _, pair := range endpoint.Networking.Addressing {
				if pair.IPV4 != "" {
					ip, err := netip.ParseAddr(pair.IPV4)
					if err != nil {
						continue
					}
					ips = append(ips, ip)
				}
				if pair.IPV6 != "" {
					ip, err := netip.ParseAddr(pair.IPV6)
					if err != nil {
						continue
					}
					ips = append(ips, ip)
				}
			}
			for _, ip := range ips {
				for _, dstCIDR := range rule.dstCIDRs {
					// We don't support heterogenenous family
					if ip.Is4() != dstCIDR.Addr().Is4() {
						continue
					}
					keys = append(keys, srv6map.VRFKey{
						SourceIP: ip,
						DestCIDR: dstCIDR,
					})
				}
			}
		}
	}
	return keys
}

// VRFRule is the internal representation of rules from IsovalentVRF.
type VRFRule struct {
	endpointSelectors []api.EndpointSelector
	dstCIDRs          []netip.Prefix
}

// deepcopy-gen cannot generate a DeepCopyInto for net.IPNet. Define by ourselves.
func (in *VRFRule) DeepCopy() *VRFRule {
	if in == nil {
		return nil
	}
	out := new(VRFRule)
	in.DeepCopyInto(out)
	return out
}

// deepcopy-gen cannot generate a DeepCopyInto for net.IPNet. Define by ourselves.
// This must be exported because zz_generated.deepcopy.go uses this.
func (in *VRFRule) DeepCopyInto(out *VRFRule) {
	if in.endpointSelectors != nil {
		out.endpointSelectors = make([]api.EndpointSelector, len(in.endpointSelectors))
		for i, selector := range in.endpointSelectors {
			selector.DeepCopyInto(&out.endpointSelectors[i])
		}
	}
	if in.dstCIDRs != nil {
		out.dstCIDRs = make([]netip.Prefix, len(in.dstCIDRs))
		copy(out.dstCIDRs, in.dstCIDRs)
	}
}

// vrfID includes policy name and namespace
type vrfID = types.NamespacedName

// selectsEndpoint determines if the given endpoint is selected by the VRFRule
// based on matching labels of policy and endpoint.
func (rule *VRFRule) selectsEndpoint(endpointLabels map[string]string) bool {
	labelsToMatch := k8sLabels.Set(endpointLabels)
	for _, selector := range rule.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

func ParseVRF(csrvrf *v1alpha1.IsovalentVRF) (*VRF, error) {
	name := csrvrf.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("IsovalentSRv6EgressPolicy must have a name")
	}

	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []netip.Prefix
	var rules []VRFRule

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	for _, rule := range csrvrf.Spec.Rules {
		for _, cidrString := range rule.DestinationCIDRs {
			cidr, err := netip.ParsePrefix(string(cidrString))
			if err != nil {
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
					api.NewESFromK8sLabelSelector("", prefixedNsSelector, selector.EndpointSelector))
			} else if selector.EndpointSelector != nil {
				endpointSelectorList = append(
					endpointSelectorList,
					api.NewESFromK8sLabelSelector("", selector.EndpointSelector))
			} else {
				return nil, fmt.Errorf("IsovalentVRF cannot have both nil namespace selector and nil pod selector")
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
		LocatorPool:       csrvrf.Spec.LocatorPoolRef,
	}, nil
}

// ParsePolicyConfigID takes a IsovalentVRF CR and returns only the
// config id.
func ParseVRFID(csrvrf *v1alpha1.IsovalentVRF) types.NamespacedName {
	return vrfID{
		Name: csrvrf.Name,
	}
}

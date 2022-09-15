// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumegressnatpolicy",path="ciliumegressnatpolicies",scope="Cluster",shortName={cenp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion
// +kubebuilder:deprecatedversion:warning="CiliumEgressNATPolicy is deprecated and will be removed in version 1.13. Use CiliumEgressGatewayPolicy instead."

type CiliumEgressNATPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumEgressNATPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumEgressNATPolicyList is a list of CiliumEgressNATPolicy objects.
type CiliumEgressNATPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEgressNATPolicy.
	Items []CiliumEgressNATPolicy `json:"items"`
}

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$`
type IPv4CIDR string

type CiliumEgressNATPolicySpec struct {
	// Egress represents a list of rules by which egress traffic is
	// filtered from the source pods.
	Egress []EgressRule `json:"egress"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []IPv4CIDR `json:"destinationCIDRs"`

	// EgressSourceIP is a source ip address that the egress traffic is
	// redirected to and SNATed with.
	//
	// Example:
	// When it is set to "192.168.1.100", matched egress packets will be
	// redirected to node with ip 192.168.1.100 and SNAT’ed with IP address 192.168.1.100.
	//
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	// +kubebuilder:validation:Optional
	EgressSourceIP string `json:"egressSourceIP,omitempty"`

	// EgressGroup represents a group of nodes which will act as egress
	// gateway for the given policy.
	//
	// +kubebuilder:validation:Optional
	EgressGroups []EgressGroup `json:"egressGroups,omitempty"`
}

// EgressRule specifies the source pods that a given egress NAT policy should
// match.
type EgressRule struct {
	// Selects Namespaces using cluster-scoped labels. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`

	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
}

// CoreCiliumEndpoint is slim version of status of CiliumEndpoint.
type CoreCiliumEndpoint struct {
	// Name indicate as CiliumEndpoint name.
	Name string `json:"name,omitempty"`
	// IdentityID is the numeric identity of the endpoint
	IdentityID int64 `json:"id,omitempty"`
	// Networking is the networking properties of the endpoint.

	// +kubebuilder:validation:Optional
	Networking *cilium_v2.EndpointNetworking `json:"networking,omitempty"`
	// Encryption is the encryption configuration of the node

	// +kubebuilder:validation:Optional
	Encryption cilium_v2.EncryptionSpec `json:"encryption,omitempty"`
	NamedPorts models.NamedPorts        `json:"named-ports,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumendpointslice",path="ciliumendpointslices",scope="Cluster",shortName={ces}
// +kubebuilder:storageversion

// CiliumEndpointSlice contains a group of CoreCiliumendpoints.
type CiliumEndpointSlice struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Namespace indicate as CiliumEndpointSlice namespace.
	// All the CiliumEndpoints within the same namespace are put together
	// in CiliumEndpointSlice.
	Namespace string `json:"namespace,omitempty"`

	// Endpoints is a list of coreCEPs packed in a CiliumEndpointSlice
	Endpoints []CoreCiliumEndpoint `json:"endpoints"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumEndpointSliceList is a list of CiliumEndpointSlice objects.
type CiliumEndpointSliceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEndpointSlice.
	Items []CiliumEndpointSlice `json:"items"`
}

// EgressGroup identifies a group of nodes that should act as egress gateways
// for a given egress NAT policy. In addition to that it also specifies the
// configuration of said nodes (which egress IP or network interface should be
// used to SNAT traffic).
type EgressGroup struct {
	// This is a label selector which selects nodes. This field follows standard label
	// selector semantics; if present but empty, it selects all nodes.
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// Interface is the network interface to which the egress IP is assigned.
	//
	// When none of the Interface or EgressIP fields is specified, the
	// policy will use the first IPv4 assigned to the interface with the
	// default route.
	Interface string `json:"interface,omitempty"`

	// EgressIP is a source IP address that the egress traffic is redirected
	// to and SNATed with.
	//
	// Example:
	// When it is set to "192.168.1.100", matched egress packets will be
	// redirected to node with IP 192.168.1.100 and SNAT’ed with IP address 192.168.1.100.
	//
	// When none of the Interface or EgressIP fields is specified, the
	// policy will use the first IPv4 assigned to the interface with the
	// default route.
	//
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	EgressIP string `json:"egressIP,omitempty"`

	// MaxGatewayNodes indicates the maximum number of nodes in the node
	// group that can operate as egress gateway simultaneously
	//
	// +kubebuilder:validation:Optional
	MaxGatewayNodes int `json:"maxGatewayNodes"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumsrv6egresspolicy",path="ciliumsrv6egresspolicies",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumSRv6EgressPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumSRv6EgressPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumSRv6EgressPolicyList is a list of CiliumSRv6EgressPolicy objects.
type CiliumSRv6EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumSRv6EgressPolicy.
	Items []CiliumSRv6EgressPolicy `json:"items"`
}

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`
type CIDR string

type CiliumSRv6EgressPolicySpec struct {
	// VRFID is the ID of the VRF in which the SIDs should be looked up.
	VRFID uint32 `json:"vrfID"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []CIDR `json:"destinationCIDRs"`

	// DestinationSID is the SID used for the SRv6 encapsulation.
	// It is in effect the IPv6 destination address of the outer IPv6 header.
	//
	// +kubebuilder:validation:Pattern=`^\s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?$`
	DestinationSID string `json:"destinationSID"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumsrv6vrf",path="ciliumsrv6vrfs",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumSRv6VRF struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumSRv6VRFSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumSRv6VRFList is a list of CiliumSRv6VRF objects.
type CiliumSRv6VRFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumSRv6VRF.
	Items []CiliumSRv6VRF `json:"items"`
}

type VRFRule struct {
	// Selectors represents a list of rules to select pods that can use a
	// given VRF.
	Selectors []EgressRule `json:"selectors"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []CIDR `json:"destinationCIDRs"`
}

type CiliumSRv6VRFSpec struct {
	// VRFID is the ID of the VRF in which the SIDs should be looked up.
	VRFID uint32 `json:"vrfID"`

	// ImportRouteTarget is the import route-target for this VRF. It is optional and,
	// if specified, will be used by the BGP manager to know in which VRF to install
	// received routes.
	ImportRouteTarget string `json:"importRouteTarget,omitempty"`

	// ExportRouteTarget is the export route-target for this VRF. It is optional and,
	// if specified, will instruct the SRv6 Manager to allocate a SID for this VRF
	// and signal the BGP manager to create VPNv4 advertisements over applicable
	// speakers.
	ExportRouteTarget string `json:"exportRouteTarget,omitempty"`

	// Rules describes what traffic is assigned to the VRF. Egress packets are matched
	// against these rules to know to in which VRF the SID should be looked up.
	Rules []VRFRule `json:"rules"`
}

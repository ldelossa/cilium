// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +genclient:nonNamespaced
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentsrv6sidmanager",path="isovalentsrv6sidmanagers",scope="Cluster",shortName={sidmanager}
// +kubebuilder:storageversion
type IsovalentSRv6SIDManager struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec of the SID Manager.
	//
	// +kubebuilder:validation:Required
	Spec IsovalentSRv6SIDManagerSpec `json:"spec"`

	// Status is a status of the SID Manager.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status *IsovalentSRv6SIDManagerStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false
type IsovalentSRv6SIDManagerList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentSRv6SIDManager `json:"items"`
}

type IsovalentSRv6SIDManagerSpec struct {
	// LocatorAllocations is a list of locators allocated for this SID manager.
	//
	// +kubebuilder:validation:Required
	// +listType=map
	// +listMapKey=poolRef
	LocatorAllocations []*IsovalentSRv6LocatorAllocation `json:"locatorAllocations"`
}

type IsovalentSRv6SIDManagerStatus struct {
	// SIDAllocations is a list of SIDs allocated by this SID manager.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=poolRef
	SIDAllocations []*IsovalentSRv6SIDAllocation `json:"sidAllocations"`
}

type IsovalentSRv6LocatorAllocation struct {
	// PoolRef is a reference to the pool that this locator is allocated from
	//
	// +kubebuilder:validation:Required
	PoolRef string `json:"poolRef"`

	// Locators is a list of locators allocated from the pool
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxItems=1
	Locators []*IsovalentSRv6Locator `json:"locators"`
}

type IsovalentSRv6Locator struct {
	// Prefix is a locator prefix.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))/([0-9]|[0-9][0-9]|1[0-1][0-9]|12[0-8])$"
	Prefix string `json:"prefix"`

	// Structure is a structure of the SID derived from this pool. This
	// structure is used for calculating the allocatable range of locators
	// and later for calculating the allocatable range of functions and
	// arguments. The allocatable locator range is calculated as follows:
	//
	// Structure.LocatorBlockLenBits + Structure.LocatorNodeLenBits - LocatorLenBits
	//
	// +kubebuilder:validation:Required
	Structure IsovalentSRv6SIDStructure `json:"structure"`

	// BehaviorType specifies the type of the behavior of SID allocated
	// from this locator. At the moment, only "Base" and "uSID" are
	// supported. "Base" flavor binds allocated SIDs to base behaviors
	// (like End.DT4). "uSID" flavor binds allocated SIDs to the behaviors
	// for uSID (like uDT4) as described in the
	// draft-filsfils-spring-net-pgm-extension-srv6-usid
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Base;uSID
	// +kubebuilder:default=Base
	BehaviorType string `json:"behaviorType"`
}

type IsovalentSRv6SIDAllocation struct {
	// PoolRef is a reference to the pool that this SID is allocated from
	//
	// +kubebuilder:validation:Required
	PoolRef string `json:"poolRef"`

	// SIDs is a list of SID allocation information
	//
	// +kubebuilder:validation:Required
	SIDs []*IsovalentSRv6SIDInfo `json:"sids"`
}

type IsovalentSRv6SIDInfo struct {
	// SID is a pair of IPv6 address and structure information
	//
	// +kubebuilder:validation:Required
	SID IsovalentSRv6SID `json:"sid"`

	// Owner is an owner of the SID
	//
	// +kubebuilder:validation:Required
	Owner string `json:"owner"`

	// MetaData is a metadata associated with the SID
	//
	// +kubebuilder:validation:Required
	MetaData string `json:"metadata"`

	// BehaviorType specifies the type of the behavior of this SID.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Base;uSID
	// +kubebuilder:default=Base
	BehaviorType string `json:"behaviorType"`

	// Behavior is an SRv6 behavior as defined in RFC8986 associated with the SID
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=End.DT4;End.DT6;End.DT46;uDT4;uDT6;uDT46
	Behavior string `json:"behavior"`
}

type IsovalentSRv6SID struct {
	// Addr is an IPv6 address represents the SID
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ipv6
	Addr string `json:"addr"`

	// Structure is a structure of this SID
	//
	// +kubebuilder:validation:Required
	Structure IsovalentSRv6SIDStructure `json:"structure"`
}

type IsovalentSRv6SIDStructure struct {
	// Locator Block length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	LocatorBlockLenBits uint8 `json:"locatorBlockLenBits"`

	// Locator Node length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	LocatorNodeLenBits uint8 `json:"locatorNodeLenBits"`

	// Function length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	FunctionLenBits uint8 `json:"functionLenBits"`

	// Argument length as described in RFC8986.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	ArgumentLenBits uint8 `json:"argumentLenBits"`
}

// +genclient
// +kubebuilder:object:root=true
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentsrv6locatorpool",path="isovalentsrv6locatorpools",scope="Cluster",shortName={locatorpool}
// +kubebuilder:storageversion

// IsovalentSRv6LocatorPool is a custom resource which is used to
// define a SID prefix and format which will be used to allocate
// SID address blocks per node.
type IsovalentSRv6LocatorPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec of the Locator Pool.
	//
	// +kubebuilder:validation:Required
	Spec IsovalentSRv6LocatorPoolSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false
type IsovalentSRv6LocatorPoolList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentSRv6LocatorPool `json:"items"`
}

type IsovalentSRv6LocatorPoolSpec struct {
	// Prefix is a locator block prefix.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))/([0-9]|[0-9][0-9]|1[0-1][0-9]|12[0-8])$"
	Prefix string `json:"prefix"`

	// LocatorLenBits is a prefix length of the locator allocated from this
	// pool. When omitted, the locator length is calculated based on the
	// structure.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	LocatorLenBits *uint8 `json:"locatorLenBits"`

	// Structure is a structure of the SID.
	//
	// +kubebuilder:validation:Required
	Structure IsovalentSRv6SIDStructure `json:"structure"`

	// BehaviorType specifies the type of the behavior of SID allocated
	// from this locator. At the moment, only "Base" and "uSID" are
	// supported. "Base" flavor binds allocated SIDs to base behaviors
	// (like End.DT4). "uSID" flavor binds allocated SIDs to the behaviors
	// for uSID (like uDT4) as described in the
	// draft-filsfils-spring-net-pgm-extension-srv6-usid
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Base;uSID
	// +kubebuilder:default=Base
	BehaviorType string `json:"behaviorType"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentsrv6egresspolicy",path="isovalentsrv6egresspolicies",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type IsovalentSRv6EgressPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec IsovalentSRv6EgressPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentSRv6EgressPolicyList is a list of IsovalentSRv6EgressPolicy objects.
type IsovalentSRv6EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentSRv6EgressPolicy.
	Items []IsovalentSRv6EgressPolicy `json:"items"`
}

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`
type CIDR string

type IsovalentSRv6EgressPolicySpec struct {
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
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentvrf",path="isovalentvrfs",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type IsovalentVRF struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec IsovalentVRFSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentVRFList is a list of IsovalentVRF objects.
type IsovalentVRFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentVRF.
	Items []IsovalentVRF `json:"items"`
}

type IsovalentVRFEgressRule struct {
	// Selects Namespaces using cluster-scoped labels. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`

	// This is a label selector which selects endpoints. This field follows
	// standard label selector semantics; if present but empty, it selects
	// all endpoints.
	EndpointSelector *slimv1.LabelSelector `json:"endpointSelector,omitempty"`
}

type IsovalentVRFRule struct {
	// Selectors represents a list of rules to select pods that can use a
	// given VRF.
	Selectors []IsovalentVRFEgressRule `json:"selectors"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []CIDR `json:"destinationCIDRs"`
}

type IsovalentVRFSpec struct {
	// VRFID is the ID of the VRF in which the SIDs should be looked up.
	VRFID uint32 `json:"vrfID"`

	// ImportRouteTarget is the import route-target for this VRF. It is optional and,
	// if specified, will be used by the BGP manager to know in which VRF to install
	// received routes.
	//
	// Deprecated: Use IsovalentBGPClusterConfig resource to define import/export route-targets.
	ImportRouteTarget string `json:"importRouteTarget,omitempty"`

	// ExportRouteTarget is the export route-target for this VRF. It is optional and,
	// if specified, will instruct the SRv6 Manager to allocate a SID for this VRF
	// and signal the BGP manager to create VPNv4 advertisements over applicable
	// speakers.
	//
	// Deprecated: Use IsovalentBGPClusterConfig resource to define import/export route-targets.
	ExportRouteTarget string `json:"exportRouteTarget,omitempty"`

	// LocatorPoolRef specifies a name of the locator pool that the SRv6
	// SID for this VRF will be allocated from.
	LocatorPoolRef string `json:"locatorPoolRef,omitempty"`

	// Rules describes what traffic is assigned to the VRF. Egress packets are matched
	// against these rules to know to in which VRF the SID should be looked up.
	Rules []IsovalentVRFRule `json:"rules"`
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// IsovalentBGPAdvertType defines type of advertisement.
//
// Note list of supported advertisements is not exhaustive and can be extended in the future.
// Consumer of this API should be able to handle unknown values.
//
// +kubebuilder:validation:Enum=PodCIDR;CiliumPodIPPool;Service;EgressGateway;SRv6LocatorPool
type IsovalentBGPAdvertType string

const (
	// BGPEGWAdvert is advertisement of egress gateway.
	BGPEGWAdvert IsovalentBGPAdvertType = "EgressGateway"

	// BGPSRv6LocatorPoolAdvert is advertisement of SRv6 locator pool routes.
	BGPSRv6LocatorPoolAdvert IsovalentBGPAdvertType = "SRv6LocatorPool"

	// BGPPodCIDRAdvert when configured, Cilium will advertise pod CIDRs to BGP peers.
	BGPPodCIDRAdvert IsovalentBGPAdvertType = "PodCIDR"

	// BGPCiliumPodIPPoolAdvert when configured, Cilium will advertise prefixes from CiliumPodIPPools to BGP peers.
	BGPCiliumPodIPPoolAdvert IsovalentBGPAdvertType = "CiliumPodIPPool"

	// BGPServiceAdvert when configured, Cilium will advertise service related routes to BGP peers.
	BGPServiceAdvert IsovalentBGPAdvertType = "Service"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgpadvertisement",path="isovalentbgpadvertisements",scope="Cluster",shortName={ibgpadvert}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// IsovalentBGPAdvertisement is the Schema for the isovalentbgpadvertisements API
type IsovalentBGPAdvertisement struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec IsovalentBGPAdvertisementSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPAdvertisementList contains a list of IsovalentBGPAdvertisement
type IsovalentBGPAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPAdvertisement.
	Items []IsovalentBGPAdvertisement `json:"items"`
}

type IsovalentBGPAdvertisementSpec struct {
	// Advertisements is a list of BGP advertisements.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Advertisements []BGPAdvertisement `json:"advertisements"`
}

type BGPAdvertisement struct {
	// AdvertisementType defines type of advertisement which has to be advertised.
	//
	// +kubebuilder:validation:Required
	AdvertisementType IsovalentBGPAdvertType `json:"advertisementType"`

	// Service defines configuration options for advertisementType service.
	//
	// +kubebuilder:validation:Optional
	Service *BGPServiceOptions `json:"service,omitempty"`

	// Selector is a label selector to select objects of the type specified by AdvertisementType.
	// If not specified, no objects of the type specified by AdvertisementType are selected for advertisement.
	//
	// +kubebuilder:validation:Optional
	Selector *slimv1.LabelSelector `json:"selector,omitempty"`

	// Attributes defines additional attributes to set to the advertised routes.
	// If not specified, no additional attributes are set.
	//
	// +kubebuilder:validation:Optional
	Attributes *v2alpha1.BGPAttributes `json:"attributes,omitempty"`
}

// BGPServiceOptions defines the configuration for Service advertisement type.
type BGPServiceOptions struct {
	// Addresses is a list of service address types which needs to be advertised via BGP.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Addresses []v2alpha1.BGPServiceAddressType `json:"addresses,omitempty"`

	// AggregationLength is the length of the prefix to be advertised.
	// If not specified, exact route is advertised with prefix length of 32 for IPv4
	// and 128 for IPv6.
	//
	// This option does not change prefix lengths of VIPs for services which have
	// externalTrafficPolicy set to Local.
	//
	// +kubebuilder:validation:Optional
	AggregationLength *int32 `json:"aggregationLength,omitempty"`
}

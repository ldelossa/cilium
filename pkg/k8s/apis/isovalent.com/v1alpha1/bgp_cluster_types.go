// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgpclusterconfig",path="isovalentbgpclusterconfigs",scope="Cluster",shortName={ibgpcluster}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// IsovalentBGPClusterConfig is the Schema for the IsovalentBGPClusterConfig API
type IsovalentBGPClusterConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired cluster configuration of the BGP control plane.
	Spec IsovalentBGPClusterConfigSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPClusterConfigList is a list of IsovalentBGPClusterConfig objects.
type IsovalentBGPClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPClusterConfig.
	Items []IsovalentBGPClusterConfig `json:"items"`
}

type IsovalentBGPClusterConfigSpec struct {
	// NodeSelector selects a group of nodes where this BGP Cluster
	// config applies.
	// If empty / nil this config applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// A list of IsovalentBGPInstance(s) which instructs
	// the BGP control plane how to instantiate virtual BGP routers.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	BGPInstances []IsovalentBGPInstance `json:"bgpInstances"`
}

type IsovalentBGPInstance struct {
	// Name is the name of the BGP instance. It is a unique identifier for the BGP instance
	// within the cluster configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalASN is the ASN of this BGP instance.
	// Supports extended 32bit ASNs.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN *int64 `json:"localASN,omitempty"`

	// Peers is a list of neighboring BGP peers for this virtual router
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []IsovalentBGPPeer `json:"peers,omitempty"`

	// VRFs is a list of VRFs for this virtual router
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=vrfRef
	VRFs []BGPVRF `json:"vrfs,omitempty"`
}

type IsovalentBGPPeer struct {
	// Name is the name of the BGP peer. It is a unique identifier for the peer within the BGP instance.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// PeerAddress is the IP address of the neighbor.
	// Supports IPv4 and IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	PeerAddress *string `json:"peerAddress,omitempty"`

	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	PeerASN *int64 `json:"peerASN,omitempty"`

	// PeerConfigRef is a reference to a peer configuration resource.
	// If not specified, the default BGP configuration is used for this peer.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRef *PeerConfigReference `json:"peerConfigRef,omitempty"`
}

// PeerConfigReference is a reference to a peer configuration resource.
type PeerConfigReference struct {
	// Group is the group of the peer config resource.
	// If not specified, the default of "isovalent.com" is used.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="isovalent.com"
	Group string `json:"group"`

	// Kind is the kind of the peer config resource.
	// If not specified, the default of "IsovalentBGPPeerConfig" is used.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="IsovalentBGPPeerConfig"
	Kind string `json:"kind"`

	// Name is the name of the peer config resource.
	// Name refers to the name of a Kubernetes object (typically a IsovalentBGPPeerConfig).
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type BGPVRF struct {
	// VRFRef is a reference to a IsovalentVRF resource. It should be the same as the name of the
	// IsovalentVRF object to which this BGPVRF is associated.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	VRFRef string `json:"vrfRef"`

	// ConfigRef is a reference to a IsovalentBGPVRFConfig resource.
	//
	// +kubebuilder:validation:Optional
	ConfigRef *string `json:"configRef,omitempty"`

	// RD is the Route Distinguisher of the VRF.
	//
	// +kubebuilder:validation:Optional
	RD *string `json:"rd,omitempty"`

	// ImportRTs is a list of route targets to import routes from.
	//
	// +kubebuilder:validation:Optional
	ImportRTs []string `json:"importRTs,omitempty"`

	// ExportRTs is a list of route targets to export routes to.
	//
	// +kubebuilder:validation:Optional
	ExportRTs []string `json:"exportRTs,omitempty"`
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +kubebuilder:object:root=true
// +genclient:nonNamespaced
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentmulticastgroup",path="isovalentmulticastgroups",scope="Cluster",shortName={imcastgroup}
// +kubebuilder:storageversion

// IsovalentMulticastGroup is the Schema for the isovalentmulticastgroups API
type IsovalentMulticastGroup struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec contains group information
	//
	// +kubebuilder:validation:Required
	Spec IsovalentMulticastGroupSpec `json:"spec"`
}

// IsovalentMulticastGroupList contains a list of IsovalentMulticastGroup
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false
type IsovalentMulticastGroupList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentMulticastGroup `json:"items"`
}

// IsovalentMulticastGroupSpec defines the desired state of IsovalentMulticastGroup
type IsovalentMulticastGroupSpec struct {
	// GroupAddrs is a list of multicast groups enabled in the cluster.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	GroupAddrs []MulticastGroupAddr `json:"groupAddrs"`
}

// MulticastGroupAddr is the IP address of a multicast group.
type MulticastGroupAddr string

// +genclient
// +kubebuilder:object:root=true
// +genclient:nonNamespaced
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentmulticastnode",path="isovalentmulticastnodes",scope="Cluster",shortName={imcastnode}
// +kubebuilder:storageversion

type IsovalentMulticastNode struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec contains node information
	//
	// +kubebuilder:validation:Required
	Spec IsovalentMulticastNodeSpec `json:"spec"`

	// Status contains node local multicast subscriber information
	//
	// +kubebuilder:validation:Optional
	Status IsovalentMulticastNodeStatus `json:"status,omitempty"`
}

// IsovalentMulticastNodeList contains a list of IsovalentMulticastNode
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false
type IsovalentMulticastNodeList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentMulticastNode `json:"items"`
}

type IsovalentMulticastNodeSpec struct {
	// NodeIP is the IP address of the node.
	//
	// +kubebuilder:validation:Required
	NodeIP string `json:"nodeIP"`
}

type IsovalentMulticastNodeStatus struct {
	// MulticastSubscribers is a list of multicast groups the node is subscribing.
	//
	// +kubebuilder:validation:Optional
	MulticastSubscribers []MulticastNodeSubscriberData `json:"multicastSubscribers,omitempty"`
}

type MulticastNodeSubscriberData struct {
	// GroupAddr is the multicast group address.
	//
	// +kubebuilder:validation:Required
	GroupAddr MulticastGroupAddr `json:"groupAddr"`
}

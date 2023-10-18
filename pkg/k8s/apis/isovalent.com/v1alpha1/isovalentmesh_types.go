// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="isovalentmeshendpoint",path="isovalentmeshendpoints",scope="Namespaced",shortName={ime}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type IsovalentMeshEndpoint struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec contains the specification for this IsovalentMeshEndpoint.
	//
	// +kubebuilder:validation:Required
	Spec IsovalentMeshEndpointSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

type IsovalentMeshEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentMeshEndpoint.
	Items []IsovalentMeshEndpoint `json:"items"`
}

// +deepequal-gen=true

type IsovalentMeshEndpointSpec struct {
	// +kubebuilder:validation:Required
	IP string `json:"ip"`
}

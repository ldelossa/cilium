// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentbgpvrfconfig",path="isovalentbgpvrfconfigs",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type IsovalentBGPVRFConfig struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec IsovalentBGPVRFConfigSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPVRFConfigList is a list of IsovalentBGPVRFConfig objects.
type IsovalentBGPVRFConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPVRFConfig.
	Items []IsovalentBGPVRFConfig `json:"items"`
}

type IsovalentBGPVRFConfigSpec struct {
	// Families provide the BGP families and their respective advertisements which
	// will be advertised over VPN.
	//
	// +kubebuilder:validation:Optional
	Families []v2alpha1.CiliumBGPFamilyWithAdverts `json:"families,omitempty"`
}

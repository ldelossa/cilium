//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package v1alpha1

import (
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SandboxPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []SandboxPolicy `json:"items,omitempty"`
}

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="sandboxpolicy",path="sandboxpolicies",scope="Cluster",shortName={}
type SandboxPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// sandbox policy specification
	Spec SandboxSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SandboxPolicyNamespacedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []SandboxPolicyNamespaced `json:"items,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="sandboxpolicynamespaced",path="sandboxpoliciesnamespaced",scope="Namespaced",shortName={}
type SandboxPolicyNamespaced struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec SandboxSpec `json:"spec"`
}

type SandboxAction struct {
	// Type defines the type of action to be taken.
	// Post: generate an event
	// Block: block the operation from hapenning (return an early EPERM error)
	// Signal: send a SIGKILL to the process
	// +kubebuilder:validation:Enum=Post;Block;Signal
	Type string `json:"type"`

	// NB(kkourt):  for now we keep things simple and define actions only as a string. In later,
	// versions we might want to support things like defining the specific signal send in the
	// application (currently, SIGKILL) or the return value returned when blocking (currently,
	// EPERM). The plan for supporting this is adding a new struct for configuring each action.
	// For example:
	//
	//     Post *SandboxPost `json:"post"`
	//     Block *SandboxBlock `json:"block"`
	//     Signal *SandboxSignal `json:"signal"`
	//
	// Above would act as a union where the tag would be the contents of .type
}

type SandboxSpec struct {
	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// Syscalls defines sets of syscalls together with actions to be taken when they are matched
	Syscalls []SandboxSyscallsSpec `json:"syscalls,omitempty"`
}

type SandboxSyscallItem struct {
	Name string `json:"name"`
}

type SandboxSyscallsSpec struct {
	// List defines a list of syscalls
	List []SandboxSyscallItem `json:"list"`

	// Op defines how the syscalls are selected
	// In: a syscall is selected if it is in List
	// NotIn: a syscall is selected if it is not in List
	// +kubebuilder:validation:Enum=In;NotIn
	// +kubebuilder:default=In
	// +kubebuilder:validation:Optional
	Op string `json:"op"`

	// Actions are the actions to be taken when a syscall is selected
	// +kubebuilder:default={{type: "Post"}, {type:"Block"}}
	// +listType=map
	// +listMapKey=type
	Actions []SandboxAction `json:"actions"`
}

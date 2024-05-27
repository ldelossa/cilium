// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BFDEchoFunctionDirection defines the direction in which the Echo Function is enabled (RFC 5880, section 2.3.).
//
// +kubebuilder:validation:Enum=Receive;Transmit
type BFDEchoFunctionDirection string

const (
	// BFDEchoFunctionDirectionReceive represents the Echo function in the direction
	// towards the cilium node (remote peer sending Echo packets towards the cilium node).
	BFDEchoFunctionDirectionReceive BFDEchoFunctionDirection = "Receive"

	// BFDEchoFunctionDirectionTransmit represents the Echo function in the direction
	// towards the remote peer (cilium node sending Echo packets towards the remote peer).
	BFDEchoFunctionDirectionTransmit BFDEchoFunctionDirection = "Transmit"
)

// +genclient
// +kubebuilder:object:root=true
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentbfdprofile",path="isovalentbfdprofiles",scope="Cluster",shortName={ibfdp}
// +kubebuilder:storageversion

// IsovalentBFDProfile allows defining BFD configuration profiles, that can be used across multiple BFD peers.
type IsovalentBFDProfile struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec contains BFD profile definition.
	//
	// +kubebuilder:validation:Required
	Spec BFDProfileSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

// IsovalentBFDProfileList contains a list of IsovalentBFDProfile objects.
type IsovalentBFDProfileList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items contains list of BFD profile definitions.
	//
	// +kubebuilder:validation:Required
	Items []IsovalentBFDProfile `json:"items"`
}

// BFDProfileSpec defines BFD configuration of a BFD profile.
type BFDProfileSpec struct {
	// ReceiveIntervalMilliseconds defines the BFD Required Min RX Interval (RFC 5880, section 4.1).
	// This is the minimum interval, in milliseconds, between received BFD Control packets that this
	// system is capable of supporting, less any jitter applied by the sender.
	//
	// If not specified, defaults to 300 milliseconds.
	// When Echo Function is active, it is automatically adapted to 1 second if lower interval was configured.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=60000
	// +kubebuilder:default=300
	ReceiveIntervalMilliseconds *int32 `json:"receiveIntervalMilliseconds,omitempty"`

	// TransmitIntervalMilliseconds defines the BFD Desired Min TX Interval (RFC 5880, section 4.1).
	// This is the minimum interval, in milliseconds, that the local system would like to use when
	// transmitting BFD Control packets, less any jitter applied.
	//
	// If not specified, defaults to 300 milliseconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=60000
	// +kubebuilder:default=300
	TransmitIntervalMilliseconds *int32 `json:"transmitIntervalMilliseconds,omitempty"`

	// DetectMultiplier defines the BFD Detection time multiplier (RFC 5880, section 4.1).
	// The negotiated transmit interval, multiplied by this value, provides the
	// Detection Time for the receiving system.
	//
	// If not specified, defaults to 3.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:default=3
	DetectMultiplier *int32 `json:"detectMultiplier,omitempty"`

	// MinimumTTL controls the minimum expected Time To Live (TTL) value for an incoming BFD control packet.
	// This value should be set to 255 for directly connected peers, and lowered for multi hop sessions,
	// based on the expected number of hops between the cilium node and the peer.
	//
	// If not specified, defaults to 255 (expecting direct connection between the cilium node and the peer).
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:default=255
	MinimumTTL *int32 `json:"minimumTTL,omitempty"`

	// EchoFunction contains configuration of the BFD Echo Function mode (RFC 5880, section 2.3.).
	//
	// If not specified, the Echo Function is completely disabled for the peer.
	//
	// +kubebuilder:validation:Optional
	EchoFunction *BFDEchoFunctionConfig `json:"echoFunction,omitempty"`
}

// BFDEchoFunctionConfig contains configuration of the BFD Echo Function (RFC 5880, section 2.3.).
// Note that this can be extended in the future when support for transmit of Echo packets is added.
type BFDEchoFunctionConfig struct {
	// Directions defines the directions in which the Echo Function is enabled.
	// If empty, the Echo Function is disabled. Single or both directions can be configured,
	// see RFC 5880, section 6.4. (The Echo Function and Asymmetry) for more details.
	//
	// Note that enabling Echo Function for a peering bound to a specific network interface
	// (either explicitly configured or auto-detected) may result into modifying sysctl kernel parameters
	// for the given interface (`send_redirects` for `Receive`, `accept_local` & `rp_filter` for `Transmit`).
	//
	// +kubebuilder:validation:Optional
	// +listType=set
	Directions []BFDEchoFunctionDirection `json:"directions,omitempty"`

	// ReceiveIntervalMilliseconds defines the BFD Required Min Echo RX Interval (RFC 5880, section 4.1).
	// This is the minimum interval, in milliseconds, between received BFD Echo packets that this
	// system is capable of supporting, less any jitter applied by the sender.
	//
	// If not specified, defaults to 300 milliseconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=60000
	// +kubebuilder:default=300
	ReceiveIntervalMilliseconds *int32 `json:"receiveIntervalMilliseconds,omitempty"`

	// TransmitIntervalMilliseconds defines the minimum interval, in milliseconds, that the local system
	// would like to use when transmitting BFD Echo packets, less any jitter applied.
	//
	// If not specified, defaults to 300 milliseconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=60000
	// +kubebuilder:default=300
	TransmitIntervalMilliseconds *int32 `json:"transmitIntervalMilliseconds,omitempty"`
}

// +genclient
// +kubebuilder:object:root=true
// +genclient:nonNamespaced
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentbfdnodeconfig",path="isovalentbfdnodeconfigs",scope="Cluster",shortName={ibfdnc}
// +kubebuilder:storageversion

// IsovalentBFDNodeConfig contains node-specific configuration for the BFD agent.
// This resource may be created and managed by Cilium operator (e.g. based on BGP config),
// which is indicated by an owner reference, and in which case it is read-only for the users.
// It may be also created by users, in which case ot is fully owned by the user.
type IsovalentBFDNodeConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the specification of the desired node-specific BFD configuration.
	//
	// +kubebuilder:validation:Required
	Spec BFDNodeConfigSpec `json:"spec"`

	// Status is the most recently observed status of the IsovalentBFDNodeConfig.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status *BFDNodeConfigStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

// IsovalentBFDNodeConfigList contains a list of IsovalentBFDNodeConfig objects.
type IsovalentBFDNodeConfigList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of IsovalentBFDNodeConfig objects.
	//
	// +kubebuilder:validation:Required
	Items []IsovalentBFDNodeConfig `json:"items"`
}

// BFDNodeConfigSpec contains node-specific configuration for the BFD agent.
type BFDNodeConfigSpec struct {
	// NodeRef is a reference to the name of the node this BFD configuration belongs to.
	//
	// +kubebuilder:validation:Required
	NodeRef string `json:"nodeRef"`

	// Peers is a list of BFD peers desired for this node.
	//
	// Note that multiple BFD sessions may be running between two systems.
	// However, each BFD session between a pair of systems MUST traverse a separate
	// network-layer path in both directions (RFC 5881, section 2).
	// To satisfy this requirement, multiple peers with the same PeerAddress are allowed
	// on the node only when they are configured with a different Interface.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []*BFDNodePeerConfig `json:"peers,omitempty"`
}

// BFDNodePeerConfig contains node-specific BFD peering configuration.
type BFDNodePeerConfig struct {
	// Name is a logical name of the peering.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// PeerAddress is the IP address of the BFD peer.
	// Supports IPv4 and IPv6 addresses. If a link-local IPv6 address is used, Interface must be specified.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ip
	PeerAddress string `json:"peerAddress"`

	// BFDProfileRef is a reference to an IsovalentBFDProfile resource name
	// containing further BFD configuration for this peering.
	//
	// The peering will not be configured until the referenced profile exists.
	//
	// +kubebuilder:validation:Required
	BFDProfileRef string `json:"bfdProfileRef,omitempty"`

	// Interface is the name of a network interface to which this session is bound to. If not specified:
	//
	// - For directly connected peers, the session is bound to an interface that is auto-detected
	//   during BFD peer reconciliation (based on the host's routing table and the LocalAddress if specified).
	//   If the routing changes and the peering needs to be re-bound to another interface,
	//   it can be done either by explicitly specifying the interface, or by any change in the BFD profile / peer config.
	//
	// - For multi-hop peers, the session is not bound to any specific interface, and no other session
	//   with the same PeerAddress can exist on the node.
	//
	// +kubebuilder:validation:Optional
	Interface *string `json:"interface,omitempty"`

	// LocalAddress is the local IP address used for the BFD peering.
	// It must match the IP address configured for this node on the remote peer.
	//
	// If not specified, it is auto-selected by the operating system using the routing table entries and/or
	// the IP address on the egress interface towards the peer.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ip
	LocalAddress *string `json:"localAddress,omitempty"`

	// EchoSourceAddress defines the IP address used as the source address when sending Echo packets for the BFD peering.
	// If not configured, the LocalAddress will be used if configured, or the auto-detected IP address
	// of the egress interface will be used, which has the following limitations:
	//
	//  - The detection of the source address happens during the session setup, and it does not
	//    automatically update upon interface address changes,
	//
	//  - Per RFC 5881, the Echo source address should not be part of the subnet bound to the interface
	//    over which the BFD Echo packet is being transmitted, and it should not be an IPv6 link-local address
	//    to preclude the remote system from generating ICMP or Neighbor Discovery Redirect messages.
	//
	// These limitations can be addressed by configuring an explicit EchoSourceAddress, which can be
	// any IP address, even non-existing on the given node.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ip
	EchoSourceAddress *string `json:"echoSourceAddress,omitempty"`
}

// +deepequal-gen=false

// BFDNodeConfigStatus contains the status of the IsovalentBFDNodeConfig resource.
type BFDNodeConfigStatus struct {
	// Conditions Represents the observations of a IsovalentBFDNodeConfig's current state.
	//
	// The "Ready" condition type can be used to observe if all BFD peers of the IsovalentBFDNodeConfig
	// have been configured successfully.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

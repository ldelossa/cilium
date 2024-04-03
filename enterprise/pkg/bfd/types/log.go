//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

const (
	// ListenAddressField is the log field key used for BFD listen address.
	ListenAddressField = "listen_address"

	// PeerAddressField is the log field key used for BFD peer IP address.
	PeerAddressField = "peer_address"

	// InterfaceNameField is the log field key used for network interface name.
	InterfaceNameField = "interface_name"

	// DiscriminatorField is the log field key used for BFD Discriminator value.
	DiscriminatorField = "discriminator"

	// SessionStateField is the log field key used for BFD session state.
	SessionStateField = "session_state"

	// MinimumTTLField is the log field key used for minimum TTL on a BFD connection.
	MinimumTTLField = "minimum_ttl"
)

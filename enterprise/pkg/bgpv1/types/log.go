// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

const (
	// EgressGatewayLogField is used as key for egress gateway in the log field.
	EgressGatewayLogField = "egress_gateway"

	// LocatorPoolLogField is used as key for SRv6 locator pool in the log field.
	LocatorPoolLogField = "locator_pool"

	// VRFLogField is used as key for VRF in the log field.
	VRFLogField = "vrf"

	// ServiceIDLogField is used as a key for service ID in the log field.
	ServiceIDLogField = "service_id"

	// ServiceAddressLogField is used as a key for service address in the log field.
	ServiceAddressLogField = "service_address"

	// BackendCountLogField is used as a key for service backend count in the log field.
	BackendCountLogField = "backend_count"

	// ToReconcileLogField is used as a key for count of items to reconcile in the log field.
	ToReconcileLogField = "to_reconcile"

	// ToWithdrawLogField is used as a key for count of items to withdraw in the log field.
	ToWithdrawLogField = "to_withdraw"
)

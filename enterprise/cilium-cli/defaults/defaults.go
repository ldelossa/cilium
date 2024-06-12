//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package defaults

// ExternalCiliumDNSProxyName is the prefix for the external Cilium DNS proxy pods (and the daemonset).
const ExternalCiliumDNSProxyName = "cilium-dnsproxy"

// EgressGatewayCIDRsDefault is the default list of CIDRs to use when allocating egress IPs for EGW IPAM tests
var EgressGatewayCIDRsDefault = []string{"172.18.0.8/30"}

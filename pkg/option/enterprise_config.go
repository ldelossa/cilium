//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package option

import "github.com/spf13/viper"

// Enterprise specific command line arguments.
const (
	// EnableIPv4EgressGateway enables the IPv4 egress gateway
	EnableIPv4EgressGatewayHA = "enable-ipv4-egress-gateway-ha"

	// EnableExternalDNSProxy enables the external DNS proxy (HA DNS proxy)
	EnableExternalDNSProxy = "external-dns-proxy"
)

type EnterpriseDaemonConfig struct {
	// Enable the HA egress gateway
	EnableIPv4EgressGatewayHA bool

	// Enable the external DNS proxy (HA DNS proxy)
	EnableExternalDNSProxy bool
}

func (ec *EnterpriseDaemonConfig) Populate(vp *viper.Viper) {
	ec.EnableIPv4EgressGatewayHA = vp.GetBool(EnableIPv4EgressGatewayHA)
	ec.EnableExternalDNSProxy = vp.GetBool(EnableExternalDNSProxy)
}

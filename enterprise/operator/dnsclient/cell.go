//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsclient

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// ServerAddresses is a list of DNS servers addresses in the form "<ip>:<port>"
	// to be used from the operator dns client.
	// If multiple servers are set, the client queries them in the order listed.
	DNSServerAddresses = "dns-server-addresses"
)

var Cell = cell.Module(
	"dns-client",
	"Isovalent DNS client",

	cell.Config(defaultConfig),
	cell.Provide(newClient),
	metrics.Metric(newMetrics),
)

type Config struct {
	DNSServerAddresses []string
}

var defaultConfig = Config{
	DNSServerAddresses: nil,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(
		DNSServerAddresses,
		def.DNSServerAddresses,
		"A list of DNS server addresses to be used by the operator DNS client for resolution of FQDNs in IsovalentFQDNGroup CRDs. Each address should be in the form \"<ip>:<port>\". "+
			"When resolving an FQDN, the operator will try to query the first server. If it fails, it will try the next one and so on, following the order specified by the user.",
	)
}

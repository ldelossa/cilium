//nolint:goheader
//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package cmd

import (
	"net/netip"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/enterprise/pkg/fqdnha/relay"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

func (d *Daemon) bootstrapFqdnRelay(stat *spanstat.SpanStat) error {
	return relay.RunServer(d, d.ipcache, stat)
}

// LookupEPByIP returns the endpoint that this IP belongs to
func (d *Daemon) LookupEPByIP(endpointIP netip.Addr) (endpoint *endpoint.Endpoint, err error) {
	return d.lookupEPByIP(endpointIP)
}

func (d *Daemon) LookupIPsBySecID(nid identity.NumericIdentity) []string {
	return d.lookupIPsBySecID(nid)
}

func (d *Daemon) LookupEP(id string) (*endpoint.Endpoint, error) {
	return d.endpointManager.Lookup(id)
}

func (d *Daemon) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	if stat == nil {
		stat = &dnsproxy.ProxyRequestContext{}
	}
	stat.DataSource = "external-proxy"
	return d.notifyOnDNSMsg(lookupTime, ep, epIPPort, serverID, serverAddr, msg, protocol, allowed, stat)
}

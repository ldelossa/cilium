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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/dns"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
)

// ErrNonExistentDomain is the error returned in case of a NXDOMAIN response
// from the DNS server.
var ErrNonExistentDomain error = errors.New("NXDOMAIN")

type Resolver interface {
	// QueryIPv4 resolves a fqdn recursively querying DNS servers with a TypeA record.
	// It returns the list of IPs, the TTLs of each IP and error in case of failure.
	QueryIPv4(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error)

	// QueryIPv4 resolves a fqdn recursively querying DNS servers with a TypeAAAA record.
	// It returns the list of IPs, the TTLs of each IP and error in case of failure.
	QueryIPv6(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error)
}

const (
	// hostConfigPath is the path of the host resolver configuration file
	hostConfigPath = "/etc/resolv.conf"
)

type params struct {
	cell.In

	Cfg Config

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle
}

type client struct {
	logger logrus.FieldLogger

	client *dns.Client
	addrs  []string
}

func newClient(p params) (Resolver, error) {
	client := &client{
		logger: p.Logger,
		client: &dns.Client{},
	}

	if len(p.Cfg.DNSServerAddresses) > 0 {
		for _, addr := range p.Cfg.DNSServerAddresses {
			if _, err := netip.ParseAddrPort(addr); err != nil {
				return nil, fmt.Errorf("unable to parse DNS server address for FQDNGroup resolution: %w", err)
			}
		}
		client.addrs = p.Cfg.DNSServerAddresses
	} else {
		addrs, err := hostResolvConf()
		if err != nil {
			return nil, fmt.Errorf("unable to read resolver config from host: %w", err)
		}
		client.addrs = addrs
	}

	return client, nil
}

func (c *client) QueryIPv4(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
	return c.query(ctx, fqdn, false)
}

func (c *client) QueryIPv6(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
	return c.query(ctx, fqdn, true)
}

func hostResolvConf() ([]string, error) {
	config, err := dns.ClientConfigFromFile(hostConfigPath)
	if err != nil {
		return nil, fmt.Errorf("%s read failed", hostConfigPath)
	}

	addresses := make([]string, 0, len(config.Servers))
	for _, srv := range config.Servers {
		addresses = append(addresses, net.JoinHostPort(srv, config.Port))
	}
	return addresses, nil
}

func (c *client) query(ctx context.Context, fqdn string, ipv6 bool) ([]netip.Addr, []time.Duration, error) {
	msg := &dns.Msg{}
	if ipv6 {
		msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeAAAA)
	} else {
		msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	}
	msg.RecursionDesired = true
	msg.Id = dns.Id()

	response, rtt, err := queryServers(ctx, c.client, msg, c.addrs)
	if err != nil {
		return nil, nil, fmt.Errorf("dns query failed: %w", err)
	}
	if response.Rcode == dns.RcodeNameError {
		return nil, nil, ErrNonExistentDomain
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("invalid answer after query: %w", err)
	}

	var queryType string
	if ipv6 {
		queryType = "AAAA"
	} else {
		queryType = "A"
	}
	c.logger.WithFields(logrus.Fields{
		"fqdn":      fqdn,
		"queryType": queryType,
		"response":  response,
	}).Debug("Received DNS query response")

	var (
		ips  []net.IP
		ttls []time.Duration
	)
	if ipv6 {
		ips, ttls = extractIPsAndTTLsIPv6(response)
	} else {
		ips, ttls = extractIPsAndTTLsIPv4(response)
	}

	netIPs := make([]netip.Addr, 0, len(ips))
	for _, addr := range ips {
		netIP, ok := ip.AddrFromIP(addr)
		if !ok {
			c.logger.WithField("addr", addr).Warning("Failed to process IP from DNS response, omitting IP from DNS response.")
			continue
		}
		netIPs = append(netIPs, netIP)
	}

	// subtract the DNS RTT to the response TTL to take
	// into account the time needed to refresh the DNS entries
	for i := range ttls {
		ttls[i] -= rtt
	}

	return netIPs, ttls, err
}

func queryServers(
	ctx context.Context,
	client *dns.Client,
	msg *dns.Msg,
	addrs []string,
) (*dns.Msg, time.Duration, error) {
	var errs []error
	for _, addr := range addrs {
		response, rtt, err := client.ExchangeContext(ctx, msg, addr)
		if err == nil {
			return response, rtt, nil
		}
		errs = append(errs, fmt.Errorf("query to server %s failed: %w", addr, err))
	}
	return nil, 0, errors.Join(errs...)
}

func extractIPsAndTTLsIPv4(msg *dns.Msg) ([]net.IP, []time.Duration) {
	var (
		ips  []net.IP
		ttls []time.Duration
	)
	for _, rr := range msg.Answer {
		record, ok := rr.(*dns.A)
		if !ok {
			// ignore non-TypeA records
			continue
		}
		ips = append(ips, record.A)
		ttls = append(ttls, time.Duration(record.Hdr.Ttl)*time.Second)
	}
	return ips, ttls
}

func extractIPsAndTTLsIPv6(msg *dns.Msg) ([]net.IP, []time.Duration) {
	var (
		ips  []net.IP
		ttls []time.Duration
	)
	for _, rr := range msg.Answer {
		record, ok := rr.(*dns.AAAA)
		if !ok {
			// ignore non-TypeAAAA records
			continue
		}
		ips = append(ips, record.AAAA)
		ttls = append(ttls, time.Duration(record.Hdr.Ttl)*time.Second)
	}
	return ips, ttls
}
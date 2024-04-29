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
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/hive"
)

func typeA(w dns.ResponseWriter, req *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(req)

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.A{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeA,
			Ttl:    1,
		},
		A: net.ParseIP("1.1.1.1"),
	}
	w.WriteMsg(m)
}

func typeAAAA(w dns.ResponseWriter, req *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(req)

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeAAAA,
			Ttl:    1,
		},
		AAAA: net.ParseIP("2001:db8::68"),
	}
	w.WriteMsg(m)
}

func server(
	ipv4Fn func(dns.ResponseWriter, *dns.Msg),
	ipv6Fn func(dns.ResponseWriter, *dns.Msg),
) (*dns.Server, net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		return nil, nil, err
	}

	mux := dns.NewServeMux()
	mux.Handle("ipv4.com", dns.HandlerFunc(ipv4Fn))
	mux.Handle("ipv6.com", dns.HandlerFunc(ipv6Fn))

	return &dns.Server{
		PacketConn: pc,
		Handler:    mux,
	}, pc, nil
}

func TestClient(t *testing.T) {
	defer goleak.VerifyNone(t)

	var client Resolver

	srv, conn, err := server(typeA, typeAAAA)
	if err != nil {
		t.Fatalf("DNS test server creation failed: %s", err)
	}

	hive := hive.New(
		cell.Provide(func() Config {
			return Config{
				DNSServerAddresses: []string{conn.LocalAddr().String()},
			}
		}),
		cell.Provide(newClient),
		cell.Provide(newMetrics),

		cell.Invoke(func(lc cell.Lifecycle) error {
			lc.Append(cell.Hook{
				OnStart: func(ctx cell.HookContext) error {
					go srv.ActivateAndServe()
					return nil
				},
				OnStop: func(ctx cell.HookContext) error {
					return srv.ShutdownContext(ctx)
				},
			})
			return nil
		}),
		cell.Invoke(func(r Resolver) {
			client = r
		}),
	)

	if err := hive.Start(hivetest.Logger(t), context.Background()); err != nil {
		t.Fatal(err)
	}

	testIPv4(t, client)
	testIPv6(t, client)

	if err := hive.Stop(hivetest.Logger(t), context.Background()); err != nil {
		t.Fatal(err)
	}
}

func testIPv4(t *testing.T, client Resolver) {
	ips, ttls, err := client.QueryIPv4(context.Background(), "ipv4.com")
	if err != nil {
		t.Fatalf("error while querying DNS server: %s", err)
	}

	if err := checkIPs([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, ips); err != nil {
		t.Fatal(err)
	}
	if err := checkTTLs([]time.Duration{time.Second}, ttls); err != nil {
		t.Fatal(err)
	}
}

func testIPv6(t *testing.T, client Resolver) {
	ips, ttls, err := client.QueryIPv6(context.Background(), "ipv6.com")
	if err != nil {
		t.Fatalf("error while querying DNS server: %s", err)
	}

	if err := checkIPs([]netip.Addr{netip.MustParseAddr("2001:db8::68")}, ips); err != nil {
		t.Fatal(err)
	}
	if err := checkTTLs([]time.Duration{time.Second}, ttls); err != nil {
		t.Fatal(err)
	}
}

func checkIPs(expected []netip.Addr, got []netip.Addr) error {
	if len(expected) != len(got) {
		return fmt.Errorf("expected %d IPs, got %v", len(expected), len(got))
	}
	for i := 0; i < len(expected); i++ {
		if expected[i] != got[i] {
			return fmt.Errorf("expected IP %v, got %v", expected[i], got[i])
		}
	}
	return nil
}

func checkTTLs(expected []time.Duration, got []time.Duration) error {
	if len(expected) != len(got) {
		return fmt.Errorf("expected %d TTLs, got %v", len(expected), len(got))
	}
	// We have to take into account the (unpredictable) RTT time,
	// so we consider acceptable a value that is in the range
	// [50% of expected TTL, 150% of expected TTL]
	for i := 0; i < len(expected); i++ {
		lowerLimit := time.Duration(float64(expected[i]) * 0.5)
		upperLimit := time.Duration(float64(expected[i]) * 1.5)
		if expected[i] < lowerLimit || expected[i] > upperLimit {
			return fmt.Errorf("expected value to be in [%v, %v], got %v", lowerLimit, upperLimit, expected[i])
		}
	}
	return nil
}

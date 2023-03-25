//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsresolver

import (
	"context"
	"net/netip"
	"time"
)

func retry(check func() error) error {
	wait := 10 * time.Millisecond

	for {
		time.Sleep(wait)
		if err := check(); err == nil {
			return nil
		}
		wait *= 2
	}
}

type mockClient struct {
	ipv4Fn func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error)
	ipv6Fn func(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error)
}

func (c *mockClient) QueryIPv4(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
	return c.ipv4Fn(ctx, fqdn)
}

func (c *mockClient) QueryIPv6(ctx context.Context, fqdn string) ([]netip.Addr, []time.Duration, error) {
	return c.ipv6Fn(ctx, fqdn)
}

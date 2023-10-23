//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cmd

import "github.com/cilium/cilium/pkg/ipam"

// GetIPv6Allocator returns the IPv6 IPAM allocator. Caller must ensure IPAM is
// initialized. Otherwise, it causes runtime error. This is only used from SRv6
// Manager to get a reference to the IPAM. Once IPAM becomes modular, we can
// remove this function.
func (d *Daemon) GetIPv6Allocator() ipam.Allocator {
	return d.ipam.IPv6Allocator
}

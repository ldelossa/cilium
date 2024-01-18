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

package doubleproxy

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
)

var _ proxy.DNSProxier = &DoubleProxy{}

// DoubleProxy is a shim for relaying proxy function calls to a local and remote proxies.
// LocalProxy is always set, RemoteProxy may be nil
type DoubleProxy struct {
	RemoteProxy proxy.DNSProxier
	LocalProxy  proxy.DNSProxier
}

func (j DoubleProxy) GetRules(u uint16) (restore.DNSRules, error) {
	return j.LocalProxy.GetRules(u)
}

func (j DoubleProxy) RemoveRestoredRules(u uint16) {
	if j.RemoteProxy != nil {
		j.RemoteProxy.RemoveRestoredRules(u)
	}
	j.LocalProxy.RemoveRestoredRules(u)
}

func (j DoubleProxy) UpdateAllowed(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error {
	err := j.LocalProxy.UpdateAllowed(endpointID, destPort, newRules)
	if err != nil {
		return err
	}
	if j.RemoteProxy != nil {
		err = j.RemoteProxy.UpdateAllowed(endpointID, destPort, newRules)
		if err != nil {
			return err
		}
	}
	return nil
}

func (j DoubleProxy) GetBindPort() uint16 {
	return j.LocalProxy.GetBindPort()
}

func (j DoubleProxy) SetRejectReply(s string) {
	j.LocalProxy.SetRejectReply(s)
	if j.RemoteProxy != nil {
		j.RemoteProxy.SetRejectReply(s)
	}
}

func (j DoubleProxy) RestoreRules(op *endpoint.Endpoint) {
	if j.RemoteProxy != nil {
		j.RemoteProxy.RestoreRules(op)
	}
	j.LocalProxy.RestoreRules(op)
}

func (j DoubleProxy) Cleanup() {
	j.LocalProxy.Cleanup()
	j.RemoteProxy.Cleanup()
}

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
	"github.com/cilium/cilium/daemon/cmd"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/remoteproxy"
	"github.com/cilium/cilium/pkg/endpoint"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
)

var _ fqdnproxy.DNSProxier = &DoubleProxy{}

// DoubleProxy is a shim for relaying proxy function calls to a local and remote proxies.
// LocalProxy is always set, RemoteProxy may be nil
type DoubleProxy struct {
	RemoteProxy fqdnproxy.DNSProxier
	LocalProxy  fqdnproxy.DNSProxier

	daemonPromise promise.Promise[*cmd.Daemon]
}

type params struct {
	cell.In

	DaemonPromise promise.Promise[*cmd.Daemon]
	RemoteProxy   *remoteproxy.RemoteFQDNProxy
	Cfg           fqdnhaconfig.Config
}

func NewDoubleProxy(
	lc cell.Lifecycle,
	p params,
) *DoubleProxy {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil
	}
	dp := &DoubleProxy{
		RemoteProxy:   p.RemoteProxy,
		daemonPromise: p.DaemonPromise,
	}
	lc.Append(dp)
	return dp
}

func (dp *DoubleProxy) Start(ctx cell.HookContext) error {
	// Wait for the daemon to be populated, at which point we can assume proxy.DefaultDNSProxy to be resolved.
	_, err := dp.daemonPromise.Await(ctx)
	if err != nil {
		return err
	}

	// TODO: get rid of the DefaultDNSProxy singleton in upstream altogether to avoid this ugly hack.
	dp.LocalProxy = proxy.DefaultDNSProxy
	proxy.DefaultDNSProxy = dp

	return nil
}

func (dp *DoubleProxy) Stop(ctx cell.HookContext) error {
	return nil
}

func (dp *DoubleProxy) GetRules(u uint16) (restore.DNSRules, error) {
	return dp.LocalProxy.GetRules(u)
}

func (dp *DoubleProxy) RemoveRestoredRules(u uint16) {
	if dp.RemoteProxy != nil {
		dp.RemoteProxy.RemoveRestoredRules(u)
	}
	dp.LocalProxy.RemoveRestoredRules(u)
}

func (dp *DoubleProxy) UpdateAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) error {
	err := dp.LocalProxy.UpdateAllowed(endpointID, destPortProto, newRules)
	if err != nil {
		return err
	}
	if dp.RemoteProxy != nil {
		err = dp.RemoteProxy.UpdateAllowed(endpointID, destPortProto, newRules)
		if err != nil {
			return err
		}
	}
	return nil
}

func (dp *DoubleProxy) GetBindPort() uint16 {
	return dp.LocalProxy.GetBindPort()
}

func (dp *DoubleProxy) SetRejectReply(s string) {
	dp.LocalProxy.SetRejectReply(s)
	if dp.RemoteProxy != nil {
		dp.RemoteProxy.SetRejectReply(s)
	}
}

func (dp *DoubleProxy) RestoreRules(op *endpoint.Endpoint) {
	if dp.RemoteProxy != nil {
		dp.RemoteProxy.RestoreRules(op)
	}
	dp.LocalProxy.RestoreRules(op)
}

func (dp *DoubleProxy) Cleanup() {
	dp.LocalProxy.Cleanup()
	dp.RemoteProxy.Cleanup()
}

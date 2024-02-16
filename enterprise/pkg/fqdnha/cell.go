//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package fqdnha

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/features"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/doubleproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/relay"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/remoteproxy"
	"github.com/cilium/cilium/pkg/ipcache"
)

var defaultConfig = config.Config{
	EnableExternalDNSProxy: false,
}

var Cell = cell.Module(
	"enterprise-fqdn-ha-proxy",
	"FQDN HA proxy",

	cell.Provide(doubleproxy.NewDoubleProxy),
	cell.Provide(relay.NewFQDNProxyAgentServer),
	cell.Provide(remoteproxy.NewRemoteFQDNProxy),

	// Convert concrete objects into more restricted interfaces used by fqdn-ha-proxy.
	cell.ProvidePrivate(func(ipcache *ipcache.IPCache) relay.IPCacheGetter { return ipcache }),

	cell.Config(defaultConfig),

	features.FeatureWithConfigT[config.Config](features.Spec{
		ID:          "FQDNHAProxy",
		Name:        "Enterprise FQDN HA Proxy",
		Description: "Enables external FQDN HA proxy for Cilium Enterprise",
		Stage:       features.Limited,
	}),

	cell.Invoke(func(
		proxyAgentServer *relay.FQDNProxyAgentServer,
		doubleProxy *doubleproxy.DoubleProxy,
		cfg config.Config,
	) {
		if !cfg.EnableExternalDNSProxy || proxyAgentServer == nil || doubleProxy == nil {
			return
		}
	}),
)

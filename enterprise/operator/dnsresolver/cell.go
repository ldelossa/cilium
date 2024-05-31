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
	"time"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/operator/dnsclient"
	"github.com/cilium/cilium/pkg/hive"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// FQDNGroupMinQueryInterval is the minimum interval between two
	// consecutive queries for resolving a FQDN belonging to an IFG.
	FQDNGroupMinQueryInterval = "fqdn-group-min-query-interval"
)

// Cell invokes the creation of the DNS resolvers manager. The manager reacts
// to the IsovalentFQDNGroup resource events, starting or stopping DNS
// resolvers to lookup the FQDNs listed in the custom resources.
var Cell = cell.Module(
	"dns-resolver",
	"Isovalent DNS resolvers manager",

	cell.Config(defaultConfig),
	cell.Provide(isovalentFQDNGroup),
	cell.Invoke(newManager),
	metrics.Metric(newMetrics),
)

// Config contains the configuration for the identity-gc.
type Config struct {
	FQDNGroupMinQueryInterval time.Duration
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(FQDNGroupMinQueryInterval, def.FQDNGroupMinQueryInterval, "Minimum interval between two consecutive queries when resolving a FQDN belonging to an IsovalentFQDNGroup")
}

var defaultConfig = Config{
	FQDNGroupMinQueryInterval: time.Minute,
}

// resolverManagerParams contains all the dependencies for the DNS resolvers manager.
// They will be provided through dependency injection.
type resolverManagerParams struct {
	cell.In

	Logger logrus.FieldLogger

	LC         cell.Lifecycle
	Shutdowner hive.Shutdowner

	Cfg               Config
	DNSClient         dnsclient.Resolver
	Clientset         k8sClient.Clientset
	FQDNGroupResource resource.Resource[*isovalent_api_v1alpha1.IsovalentFQDNGroup]

	Metrics *Metrics
}

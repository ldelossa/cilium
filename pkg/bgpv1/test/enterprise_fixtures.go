// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"

	enterprisebgpv1 "github.com/cilium/cilium/enterprise/pkg/bgpv1"
	enterprisereconciler "github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/pkg/hive"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/service"
)

// CiliumASN is BGP ASN number used in test cilium instance
var CiliumASN = ciliumASN

// EnterpriseFixture is the test fixture for testing enterprise BGP features.
type EnterpriseFixture struct {
	*fixture
}

// EnterpriseFixtureConfig holds configuration for the enterprise test fixture.
type EnterpriseFixtureConfig struct {
	ReconcilerConfig      *enterprisereconciler.Config
	SvcHealthCheckManager service.ServiceHealthCheckManager
}

// newEnterpriseFixture creates a new test fixture with enterprise functionality.
func newEnterpriseFixture(conf *EnterpriseFixtureConfig) *EnterpriseFixture {
	f := &EnterpriseFixture{}

	f.fixture = newFixture(newFixtureConf())

	// create a new hive which also contains enterprise cells
	f.cells = append(f.cells,
		// enterprise bgpv1 cell
		enterprisebgpv1.Cell,
	)
	if conf.SvcHealthCheckManager != nil {
		// enterprise LBServiceReconciler dependency
		f.cells = append(f.cells,
			cell.Provide(func() service.ServiceHealthCheckManager {
				return conf.SvcHealthCheckManager
			}),
		)
	}
	f.hive = hive.New(f.cells...)

	if conf.ReconcilerConfig != nil {
		// override enterprise reconciler config
		hive.AddConfigOverride(f.hive, func(cfg *enterprisereconciler.Config) {
			// requires value overwrite
			cfg.SvcHealthCheckingEnabled = conf.ReconcilerConfig.SvcHealthCheckingEnabled
		})
	}

	return f
}

func (f EnterpriseFixture) FakeClientSet() *k8sClient.FakeClientset {
	return f.fakeClientSet
}

func (f EnterpriseFixture) PolicyClient() v2alpha1.CiliumBGPPeeringPolicyInterface {
	return f.policyClient
}

func (f EnterpriseFixture) ConfigPolicy() *cilium_api_v2alpha1.CiliumBGPPeeringPolicy {
	return &f.config.policy
}

// EnterpriseSetup configures the test environment with enterprise cilium instance and one gobgp peer.
func EnterpriseSetup(t testing.TB, ctx context.Context, fixConfig *EnterpriseFixtureConfig) (peers []GoBGPInstance, f *EnterpriseFixture, cleanup func(), err error) {
	f = newEnterpriseFixture(fixConfig)

	var gobgpPeers []*goBGP
	gobgpPeers, cleanup, err = start(ctx, t, []gobgpConfig{gobgpConf}, f.fixture)

	for _, peer := range gobgpPeers {
		peers = append(peers, peer)
	}
	return
}

// SetupSingleNeighbor sets up single BGP neighbor on cilium virtual router.
func SetupSingleNeighbor(ctx context.Context, f *EnterpriseFixture) error {
	return setupSingleNeighbor(ctx, f.fixture, gobgpASN)
}

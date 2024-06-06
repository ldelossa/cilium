//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh"
	cmcommon "github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	cectnat "github.com/cilium/cilium/enterprise/pkg/maps/ctnat"
)

func TestClusterMeshWithOverlappingPodCIDR(t *testing.T) {
	testutils.IntegrationTest(t)

	kvstore.SetupDummy(t, "etcd")

	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	<-mgr.InitIdentityAllocator(nil)
	t.Cleanup(mgr.Close)

	maps := cectnat.NewFakePerCluster(true, true)
	cinfo := cmtypes.ClusterInfo{ID: 99, Name: "foo"}
	cm := clustermesh.NewClusterMesh(hivetest.Lifecycle(t), clustermesh.Configuration{
		Config:            cmcommon.Config{ClusterMeshConfig: t.TempDir()},
		ClusterInfo:       cinfo,
		ClusterIDsManager: newClusterIDManager(logging.DefaultLogger, cinfo, maps),

		RemoteIdentityWatcher: mgr,
		StoreFactory:          store.NewFactory(store.MetricsProvider()),

		Metrics:       clustermesh.NewMetrics(),
		CommonMetrics: cmcommon.MetricsProvider("foo")(),
	})
	require.NotNil(t, cm, "Failed to initialize clustermesh")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel the context so that Run() terminates immediately

	// Ensure that a cluster with config can connect
	cfg := cmtypes.CiliumClusterConfig{ID: 1}
	ready := make(chan error, 1)
	rc := cm.NewRemoteCluster("cluster1", nil)
	rc.Run(ctx, kvstore.Client(), cfg, ready)
	require.NoError(t, <-ready)

	// Ensure that a cluster without config can't connect
	ready = make(chan error, 1)
	cm.NewRemoteCluster("cluster2", nil).Run(ctx, kvstore.Client(), cmtypes.CiliumClusterConfig{}, ready)
	require.ErrorContains(t, <-ready, "ClusterID 0 is reserved")

	// Ensure that a cluster with the same ClusterID can't connect
	ready = make(chan error, 1)
	cm.NewRemoteCluster("cluster3", nil).Run(ctx, kvstore.Client(), cfg, ready)
	require.ErrorContains(t, <-ready, "clusterID 1 is already used")

	// Ensure that per-cluster maps are created for cluster1
	require.True(t, maps.CT().Has(cfg.ID), "CT maps not initialized correctly")
	require.True(t, maps.NAT().Has(cfg.ID), "NAT maps not initialized correctly")

	// Reconnect cluster with changed ClusterID
	newcfg := cmtypes.CiliumClusterConfig{ID: 255}
	ready = make(chan error, 1)
	rc.Run(ctx, kvstore.Client(), newcfg, ready)
	require.NoError(t, <-ready)

	// Ensure the old per-cluster maps are deleted and new per-cluster maps are created
	require.False(t, maps.CT().Has(cfg.ID), "CT maps not released correctly")
	require.False(t, maps.NAT().Has(cfg.ID), "NAT maps not released correctly")

	require.True(t, maps.CT().Has(newcfg.ID), "CT maps not initialized correctly")
	require.True(t, maps.NAT().Has(newcfg.ID), "NAT maps not initialized correctly")

	// Disconnect cluster
	rc.Remove()

	require.False(t, maps.CT().Has(newcfg.ID), "CT maps not released correctly")
	require.False(t, maps.NAT().Has(newcfg.ID), "NAT maps not released correctly")
}

func TestClusterMeshWithOverlappingPodCIDRRestart(t *testing.T) {
	testutils.IntegrationTest(t)

	kvstore.SetupDummy(t, "etcd")

	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	<-mgr.InitIdentityAllocator(nil)
	t.Cleanup(mgr.Close)

	maps := cectnat.NewFakePerCluster(true, true)

	// Emulate the situation that user disconnected cluster during Cilium restart
	oldcfg := cmtypes.CiliumClusterConfig{ID: 255}
	err := maps.CT().CreateClusterCTMaps(oldcfg.ID)
	require.NoError(t, err, "Failed to update CT maps")
	err = maps.NAT().CreateClusterNATMaps(oldcfg.ID)
	require.NoError(t, err, "Failed to update NAT maps")

	cinfo := cmtypes.ClusterInfo{ID: 99, Name: "foo"}
	idsMgr := newClusterIDManager(logging.DefaultLogger, cinfo, maps)
	cm := clustermesh.NewClusterMesh(hivetest.Lifecycle(t), clustermesh.Configuration{
		Config:            cmcommon.Config{ClusterMeshConfig: t.TempDir()},
		ClusterInfo:       cinfo,
		ClusterIDsManager: idsMgr,

		RemoteIdentityWatcher: mgr,
		StoreFactory:          store.NewFactory(store.MetricsProvider()),

		Metrics:       clustermesh.NewMetrics(),
		CommonMetrics: cmcommon.MetricsProvider("foo")(),
	})
	require.NotNil(t, cm, "Failed to initialize clustermesh")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel the context so that Run() terminates immediately

	// "Connect" a new cluster
	cfg := cmtypes.CiliumClusterConfig{ID: 1}
	ready := make(chan error, 1)
	cm.NewRemoteCluster("cluster1", nil).Run(ctx, kvstore.Client(), cfg, ready)
	require.NoError(t, <-ready)

	// Trigger cleanup
	idsMgr.cleanupStalePerClusterMaps()

	// Ensure that the maps for the connected cluster are kept
	require.True(t, maps.CT().Has(cfg.ID), "CT maps not initialized correctly")
	require.True(t, maps.NAT().Has(cfg.ID), "NAT maps not initialized correctly")

	// Ensure that the stale maps are deleted
	require.False(t, maps.CT().Has(oldcfg.ID), "CT maps not released correctly")
	require.False(t, maps.NAT().Has(oldcfg.ID), "NAT maps not released correctly")
}

func TestClusterIDManagerReserved(t *testing.T) {
	cinfo := cmtypes.ClusterInfo{ID: 99, Name: "foo"}
	maps := cectnat.NewFakePerCluster(true, true)
	mgr := newClusterIDManager(logging.DefaultLogger, cinfo, maps)

	require.Error(t, mgr.ReserveClusterID(cmtypes.ClusterIDUnset), "Reserving ClusterID 0 should fail")
	require.False(t, maps.CT().Has(cmtypes.ClusterIDUnset), "CT maps should not be created for ClusterID 0")
	require.False(t, maps.NAT().Has(cmtypes.ClusterIDUnset), "CT maps should not be created for ClusterID 0")

	// Releasing ClusterID 0 should be a no-op
	err := maps.CT().CreateClusterCTMaps(cmtypes.ClusterIDUnset)
	require.NoError(t, err, "Failed to update CT maps")
	err = maps.NAT().CreateClusterNATMaps(cmtypes.ClusterIDUnset)
	require.NoError(t, err, "Failed to update NAT maps")

	mgr.ReleaseClusterID(cmtypes.ClusterIDUnset)
	require.True(t, maps.CT().Has(cmtypes.ClusterIDUnset), "CT maps should not be deleted for ClusterID 0")
	require.True(t, maps.NAT().Has(cmtypes.ClusterIDUnset), "CT maps should not be deleted for ClusterID 0")

	require.Error(t, mgr.ReserveClusterID(cinfo.ID), "Reserving the local ClusterID should fail")
	require.False(t, maps.CT().Has(cinfo.ID), "CT maps should not be created for the local ClusterID")
	require.False(t, maps.NAT().Has(cinfo.ID), "CT maps should not be created for the local ClusterID")
}

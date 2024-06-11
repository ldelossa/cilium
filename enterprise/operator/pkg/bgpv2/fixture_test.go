// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/time"
)

var (
	TestTimeout = 10 * time.Second
)

type fixture struct {
	hive                *hive.Hive
	fakeClientSet       *k8s_client.FakeClientset
	isoClusterClient    isovalent_client_v1alpha1.IsovalentBGPClusterConfigInterface
	isoPeerConfClient   isovalent_client_v1alpha1.IsovalentBGPPeerConfigInterface
	isoAdvertClient     isovalent_client_v1alpha1.IsovalentBGPAdvertisementInterface
	isoNodeConfClient   isovalent_client_v1alpha1.IsovalentBGPNodeConfigInterface
	isoNodeConfORClient isovalent_client_v1alpha1.IsovalentBGPNodeConfigOverrideInterface

	// oss clients
	ossClusterClient    cilium_client_v2alpha1.CiliumBGPClusterConfigInterface
	ossPeerConfClient   cilium_client_v2alpha1.CiliumBGPPeerConfigInterface
	ossAdvertClient     cilium_client_v2alpha1.CiliumBGPAdvertisementInterface
	ossNodeConfClient   cilium_client_v2alpha1.CiliumBGPNodeConfigInterface
	ossNodeConfORClient cilium_client_v2alpha1.CiliumBGPNodeConfigOverrideInterface

	// node client
	nodeClient cilium_client_v2.CiliumNodeInterface
}

func newFixture(ctx context.Context, req *require.Assertions) (*fixture, func()) {
	type watchSync struct {
		once    sync.Once
		watchCh chan struct{}
	}

	var resourceWatch = map[string]*watchSync{
		v1alpha1.IsovalentBGPClusterConfigPluralName:      {watchCh: make(chan struct{})},
		v1alpha1.IsovalentBGPPeerConfigPluralName:         {watchCh: make(chan struct{})},
		v1alpha1.IsovalentBGPAdvertisementPluralName:      {watchCh: make(chan struct{})},
		v1alpha1.IsovalentBGPNodeConfigPluralName:         {watchCh: make(chan struct{})},
		v1alpha1.IsovalentBGPNodeConfigOverridePluralName: {watchCh: make(chan struct{})},
	}

	f := &fixture{}
	f.fakeClientSet, _ = k8s_client.NewFakeClientset()

	watchReactorFn := func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		w := action.(k8sTesting.WatchAction)
		gvr := w.GetResource()
		ns := w.GetNamespace()
		watchTracker, err := f.fakeClientSet.CiliumFakeClientset.Tracker().Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		watchSync, exists := resourceWatch[w.GetResource().Resource]
		if !exists {
			return false, watchTracker, nil
		}

		watchSync.once.Do(func() { close(watchSync.watchCh) })
		return true, watchTracker, nil
	}

	watcherReadyFn := func() {
		var group sync.WaitGroup
		for res, w := range resourceWatch {
			group.Add(1)
			go func(res string, w *watchSync) {
				defer group.Done()
				select {
				case <-w.watchCh:
				case <-ctx.Done():
					req.Failf("init failed", "%s watcher not initialized", res)
				}
			}(res, w)
		}
		group.Wait()
	}

	// enterprise clients
	f.isoClusterClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPClusterConfigs()
	f.isoPeerConfClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPPeerConfigs()
	f.isoAdvertClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPAdvertisements()
	f.isoNodeConfClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPNodeConfigs()
	f.isoNodeConfORClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPNodeConfigOverrides()

	// oss clients
	f.ossClusterClient = f.fakeClientSet.CiliumV2alpha1().CiliumBGPClusterConfigs()
	f.ossPeerConfClient = f.fakeClientSet.CiliumV2alpha1().CiliumBGPPeerConfigs()
	f.ossAdvertClient = f.fakeClientSet.CiliumV2alpha1().CiliumBGPAdvertisements()
	f.ossNodeConfClient = f.fakeClientSet.CiliumV2alpha1().CiliumBGPNodeConfigs()
	f.ossNodeConfORClient = f.fakeClientSet.CiliumV2alpha1().CiliumBGPNodeConfigOverrides()

	// node client
	f.nodeClient = f.fakeClientSet.CiliumV2().CiliumNodes()

	f.fakeClientSet.CiliumFakeClientset.PrependWatchReactor("*", watchReactorFn)

	f.hive = hive.New(
		cell.Provide(
			k8s.CiliumBGPPeerConfigResource,
			k8s.CiliumBGPAdvertisementResource,
			k8s.CiliumBGPNodeConfigResource,
			operatorK8s.CiliumBGPClusterConfigResource,
			operatorK8s.CiliumBGPNodeConfigOverrideResource,
		),

		cell.Provide(func(lc cell.Lifecycle, c k8s_client.Clientset) resource.Resource[*cilium_v2.CiliumNode] {
			return resource.New[*cilium_v2.CiliumNode](
				lc, utils.ListerWatcherFromTyped[*cilium_v2.CiliumNodeList](
					c.CiliumV2().CiliumNodes(),
				),
			)
		}),

		cell.Provide(func() k8s_client.Clientset {
			return f.fakeClientSet
		}),

		Cell,
	)

	hive.AddConfigOverride(f.hive, func(cfg *config.Config) { cfg.Enabled = true })

	return f, watcherReadyFn
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bfd

import (
	"context"

	"sync"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"

	bgpv2config "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	client_ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	client_isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/time"
)

var (
	TestTimeout = 5 * time.Second
)

type fixture struct {
	hive          *hive.Hive
	fakeClientSet *k8sclient.FakeClientset

	ciliumNodeClient            client_ciliumv2.CiliumNodeInterface
	bgpClusterConfigClient      client_isovalentv1alpha1.IsovalentBGPClusterConfigInterface
	bgpPeerConfigClient         client_isovalentv1alpha1.IsovalentBGPPeerConfigInterface
	bfdNodeConfigClient         client_isovalentv1alpha1.IsovalentBFDNodeConfigInterface
	bfdNodeConfigOverrideClient client_isovalentv1alpha1.IsovalentBFDNodeConfigOverrideInterface
}

func newFixture(ctx context.Context, req *require.Assertions) (*fixture, func()) {
	type watchSync struct {
		once    sync.Once
		watchCh chan struct{}
	}

	var resourceWatch = map[string]*watchSync{
		ciliumv2.CNPluralName: {watchCh: make(chan struct{})},
		isovalentv1alpha1.IsovalentBGPClusterConfigPluralName:      {watchCh: make(chan struct{})},
		isovalentv1alpha1.IsovalentBGPPeerConfigPluralName:         {watchCh: make(chan struct{})},
		isovalentv1alpha1.IsovalentBFDNodeConfigPluralName:         {watchCh: make(chan struct{})},
		isovalentv1alpha1.IsovalentBFDNodeConfigOverridePluralName: {watchCh: make(chan struct{})},
	}

	f := &fixture{}
	f.fakeClientSet, _ = k8sclient.NewFakeClientset()

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

	f.ciliumNodeClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2().CiliumNodes()
	f.bgpClusterConfigClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBGPClusterConfigs()
	f.bgpPeerConfigClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPPeerConfigs()
	f.bfdNodeConfigClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBFDNodeConfigs()
	f.bfdNodeConfigOverrideClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBFDNodeConfigOverrides()

	f.fakeClientSet.CiliumFakeClientset.PrependWatchReactor("*", watchReactorFn)

	f.hive = hive.New(
		Cell,

		cell.Config(bgpv2config.Config{Enabled: true}),
		cell.Provide(
			k8s.IsovalentBGPClusterConfigResource,
			k8s.IsovalentBGPPeerConfigResource,
		),

		cell.Provide(func(lc cell.Lifecycle, c k8sclient.Clientset) resource.Resource[*ciliumv2.CiliumNode] {
			return resource.New[*ciliumv2.CiliumNode](
				lc, utils.ListerWatcherFromTyped[*ciliumv2.CiliumNodeList](
					c.CiliumV2().CiliumNodes(),
				),
			)
		}),

		cell.Provide(func() k8sclient.Clientset {
			return f.fakeClientSet
		}),
	)

	hive.AddConfigOverride(f.hive, func(cfg *types.BFDConfig) { cfg.BFDEnabled = true })

	return f, watcherReadyFn
}

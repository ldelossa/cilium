// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	bgptypes "github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	clientv1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

const (
	bfdTestTimeout = 5 * time.Second
)

type bfdTestFixture struct {
	hive *hive.Hive

	router      *bfdFakeRouter
	reconciler  *BFDStateReconciler
	instance    *instance.BGPInstance
	bgpSignaler *signaler.BGPCPSignaler

	db            *statedb.DB
	bfdPeersTable statedb.RWTable[*types.BFDPeerStatus]
	pcClient      clientv1alpha1.IsovalentBGPPeerConfigInterface
}

func newBFDTestFixture(t *testing.T, ctx context.Context, nodeInstance *isovalentv1alpha1.IsovalentBGPNodeInstance) (*bfdTestFixture, func()) {
	var pcOnce sync.Once
	pcWatchStarted := make(chan struct{})

	router := newBFDFakeRouter()
	f := &bfdTestFixture{
		router: router,
		instance: &instance.BGPInstance{
			Router:   router,
			Metadata: make(map[string]any),
		},
	}

	f.hive = hive.New(
		// test module so that BFDStateReconciler gets a job.Group
		cell.Module("bfd-state-reconciler-test", "BFD State Reconciler test",
			cell.Config(config.Config{
				Enabled: true,
			}),
			cell.Config(types.BFDConfig{
				BFDEnabled: true,
			}),

			cell.Provide(
				NewBFDStateReconciler,

				signaler.NewBGPCPSignaler,
				func() paramUpgrader {
					return newUpgraderMock(nodeInstance)
				},

				types.NewBFDPeersTable,
				statedb.RWTable[*types.BFDPeerStatus].ToTable,

				k8s.IsovalentBGPPeerConfigResource,
				k8sclient.NewFakeClientset,
			),

			cell.Invoke(func(p BFDStateReconcilerIn) {
				out := NewBFDStateReconciler(p)
				f.reconciler = out.Reconciler.(*BFDStateReconciler)
			}),
			cell.Invoke(func(sig *signaler.BGPCPSignaler) {
				f.bgpSignaler = sig
			}),

			cell.Invoke(statedb.RegisterTable[*types.BFDPeerStatus]),
			cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*types.BFDPeerStatus]) {
				f.db = db
				f.bfdPeersTable = table
			}),

			cell.Invoke(func(clientset *k8sclient.FakeClientset) {
				f.pcClient = clientset.IsovalentV1alpha1().IsovalentBGPPeerConfigs()
				clientset.CiliumFakeClientset.PrependWatchReactor("*",
					func(action k8stesting.Action) (handled bool, ret watch.Interface, err error) {
						w := action.(k8stesting.WatchAction)
						gvr := w.GetResource()
						ns := w.GetNamespace()
						watch, err := clientset.CiliumFakeClientset.Tracker().Watch(gvr, ns)
						if err != nil {
							return false, nil, err
						}
						if w.GetResource().Resource == isovalentv1alpha1.IsovalentBGPPeerConfigPluralName {
							pcOnce.Do(func() { close(pcWatchStarted) })
							return true, watch, nil
						}
						return false, watch, nil
					})
			}),
		),
	)

	watchersReadyFn := func() {
		select {
		case <-pcWatchStarted:
		case <-ctx.Done():
			t.Fatalf("%s is not initialized", isovalentv1alpha1.IsovalentBGPPeerConfigPluralName)
		}
	}
	return f, watchersReadyFn
}

type bfdFakeRouter struct {
	bgptypes.FakeRouter
	resetPeersCh chan string
}

func newBFDFakeRouter() *bfdFakeRouter {
	return &bfdFakeRouter{
		resetPeersCh: make(chan string, 10),
	}
}

func (r *bfdFakeRouter) ResetNeighbor(ctx context.Context, rr bgptypes.ResetNeighborRequest) error {
	r.resetPeersCh <- rr.PeerAddress
	return nil
}

func TestBFDStateReconciler(t *testing.T) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	var (
		peer1Addr = netip.MustParseAddr("10.0.0.1")
		peer2Addr = netip.MustParseAddr("10.0.0.2")
		peer3Addr = netip.MustParseAddr("10.0.0.3")
	)

	peerConfigBFDEnabled := &isovalentv1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bfd-enabled",
		},
		Spec: isovalentv1alpha1.IsovalentBGPPeerConfigSpec{
			BFDProfileRef: ptr.To[string]("frr"),
		},
	}
	peerConfigBFDDisabled := &isovalentv1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bfd-disabled",
		},
		Spec: isovalentv1alpha1.IsovalentBGPPeerConfigSpec{},
	}

	var nodeInstance = &isovalentv1alpha1.IsovalentBGPNodeInstance{
		Name:     "test-instance",
		LocalASN: ptr.To[int64](65001),
		Peers: []isovalentv1alpha1.IsovalentBGPNodePeer{
			{
				PeerAddress: ptr.To[string](peer1Addr.String()),
				PeerConfigRef: &isovalentv1alpha1.PeerConfigReference{
					Name: peerConfigBFDEnabled.Name,
				},
			},
			{
				PeerAddress: ptr.To[string](peer2Addr.String()),
				PeerConfigRef: &isovalentv1alpha1.PeerConfigReference{
					Name: peerConfigBFDEnabled.Name,
				},
			},
			{
				PeerAddress: ptr.To[string](peer3Addr.String()),
				PeerConfigRef: &isovalentv1alpha1.PeerConfigReference{
					Name: peerConfigBFDDisabled.Name,
				},
			},
		},
	}
	var ossNodeInstance = &v2alpha1.CiliumBGPNodeInstance{
		Name:     nodeInstance.Name,
		LocalASN: nodeInstance.LocalASN,
	}
	for _, peer := range nodeInstance.Peers {
		ossNodeInstance.Peers = append(ossNodeInstance.Peers, v2alpha1.CiliumBGPNodePeer{
			PeerAddress: peer.PeerAddress,
			PeerConfigRef: &v2alpha1.PeerConfigReference{
				Name: peer.PeerConfigRef.Name,
			},
		})
	}

	var table = []struct {
		name          string
		desiredConfig *isovalentv1alpha1.IsovalentBGPNodeInstance
		peerChanges   []*types.BFDPeerStatus
		deletePeers   bool
		expectSignal  bool
		expectReset   []string
	}{
		{
			name:          "peer 1 goes AdminDown",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateAdminDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: false, // nothing should happen
		},
		{
			name:          "peer 1 goes Init",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: false, // nothing should happen
		},
		{
			name:          "peer 1 goes Down",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: true,
			// no reset as was not Up previously
		},
		{
			name:          "peer 1 goes Up",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 1 goes Down - reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
				},
			},
			expectSignal: true,
			expectReset:  []string{peer1Addr.String()},
		},
		{
			name:          "peer 1 stays Down - no action",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
				},
			},
			expectSignal: false,
		},
		{
			name:          "peer 1 goes Up again",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 1 goes Down again - reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
			expectReset:  []string{peer1Addr.String()},
		},
		{
			name:          "peer 2 goes Down",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: true,
			// no reset as was not Up previously
		},
		{
			name:          "peer 2 goes Up",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 2 goes Down - reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
			expectReset:  []string{peer2Addr.String()},
		},
		{
			name:          "peer 2 goes Up once more",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 2 goes Down - remote AdminDown",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateAdminDown,
					},
				},
			},
			expectSignal: true,
			// no reset as remote is AdminDown
		},
		{
			name:          "peer 2 goes Up again",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 2 goes AdminDown",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateAdminDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
				},
			},
			expectSignal: false,
			// no reset, as we are admin down
		},
		{
			name:          "peer 3 goes Down",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer3Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: true,
			// no reset as was not Up previously / and BFD is not configured
		},
		{
			name:          "peer 3 goes Up",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer3Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 3 goes Down - no reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer3Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
			// no reset as BFD is not configured
		},
	}

	// create test fixture
	testCtx, cancel := context.WithTimeout(context.Background(), bfdTestTimeout)
	t.Cleanup(func() {
		cancel()
	})
	f, waitWatchersReady := newBFDTestFixture(t, testCtx, nodeInstance)

	// start the test hive
	log := hivetest.Logger(t)
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})

	// wait until the watchers are ready
	waitWatchersReady()

	// configure Peer configs
	_, err = f.pcClient.Create(testCtx, peerConfigBFDEnabled, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.pcClient.Create(testCtx, peerConfigBFDDisabled, metav1.CreateOptions{})
	require.NoError(t, err)

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// write peer changes to statedb
			txn := f.db.WriteTxn(f.bfdPeersTable)
			for _, peer := range tt.peerChanges {
				if tt.deletePeers {
					_, _, err = f.bfdPeersTable.Delete(txn, peer)
				} else {
					_, _, err = f.bfdPeersTable.Insert(txn, peer)
				}
				require.NoError(t, err)
			}
			txn.Commit()

			if tt.expectSignal {
				// wait for BGP signal
				select {
				case <-f.bgpSignaler.Sig:
				case <-testCtx.Done():
					t.Fatalf("missed expected BGP reconciliation signal")
				}

				// run reconciliation
				reconcileParams := reconcilerv2.ReconcileParams{
					BGPInstance:   f.instance,
					DesiredConfig: ossNodeInstance,
				}
				err = f.reconciler.Reconcile(testCtx, reconcileParams)
				require.NoError(t, err)
			} else {
				require.Empty(t, f.bgpSignaler.Sig, "unexpected BGP reconciliation signal")
			}

			if len(tt.expectReset) > 0 {
				// check that expected sessions have been reset
				for range tt.expectReset {
					select {
					case reset := <-f.router.resetPeersCh:
						require.Contains(t, tt.expectReset, reset)
					case <-testCtx.Done():
						t.Fatalf("missed expected peer reset")
					}
				}
			} else {
				// check no session have been reset
				require.Empty(t, f.router.resetPeersCh, "unexpected peer reset")
			}
		})
	}
}

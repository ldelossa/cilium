//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"context"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	clientv1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/statedb"
)

const (
	testNodeName = "test-node"
)

type testFixture struct {
	hive *hive.Hive

	ncClient      clientv1alpha1.IsovalentBFDNodeConfigInterface
	profileClient clientv1alpha1.IsovalentBFDProfileInterface

	db        *statedb.DB
	peerTable statedb.RWTable[*types.BFDPeerStatus]
}

func newTestFixture(t *testing.T, ctx context.Context) (*testFixture, func()) {
	var ncOnce, peerOnce sync.Once
	ncWatchStarted, profileWatchStarted := make(chan struct{}), make(chan struct{})
	f := &testFixture{}

	f.hive = hive.New(
		Cell,
		cell.Provide(
			func() types.BFDServer {
				return newFakeBFDServer()
			},
		),
		cell.Config(types.BFDConfig{
			BFDEnabled: true,
		}),

		cell.Provide(
			k8sclient.NewFakeClientset,
		),

		cell.Provide(func() *node.LocalNodeStore {
			return node.NewTestLocalNodeStore(node.LocalNode{
				Node: nodetypes.Node{
					Name: testNodeName,
				},
			})
		}),

		cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*types.BFDPeerStatus]) {
			f.db = db
			f.peerTable = table
		}),

		cell.Invoke(func(clientset *k8sclient.FakeClientset) {
			f.ncClient = clientset.IsovalentV1alpha1().IsovalentBFDNodeConfigs()
			f.profileClient = clientset.IsovalentV1alpha1().IsovalentBFDProfiles()

			// catch-all watch reactor that allows us to inject the WatchStarted channels
			clientset.CiliumFakeClientset.PrependWatchReactor("*",
				func(action k8stesting.Action) (handled bool, ret watch.Interface, err error) {
					w := action.(k8stesting.WatchAction)
					gvr := w.GetResource()
					ns := w.GetNamespace()
					watch, err := clientset.CiliumFakeClientset.Tracker().Watch(gvr, ns)
					if err != nil {
						return false, nil, err
					}
					switch w.GetResource().Resource {
					case v1alpha1.IsovalentBFDNodeConfigPluralName:
						ncOnce.Do(func() { close(ncWatchStarted) })
					case v1alpha1.IsovalentBFDProfilePluralName:
						peerOnce.Do(func() { close(profileWatchStarted) })
					default:
						return false, watch, nil
					}
					return true, watch, nil
				})
		}),
	)

	// blocks until watchers are initialized (call before the test starts)
	watchersReadyFn := func() {
		select {
		case <-ncWatchStarted:
		case <-ctx.Done():
			t.Fatalf("%s is not initialized", v1alpha1.IsovalentBFDNodeConfigPluralName)
		}

		select {
		case <-profileWatchStarted:
		case <-ctx.Done():
			t.Fatalf("%s is not initialized", v1alpha1.IsovalentBFDProfilePluralName)
		}
	}
	return f, watchersReadyFn
}

type fakeBFDServer struct {
	statusCh chan types.BFDPeerStatus
	mcast    stream.Observable[types.BFDPeerStatus]
	connect  func(context.Context)
}

func newFakeBFDServer() *fakeBFDServer {
	s := &fakeBFDServer{
		statusCh: make(chan types.BFDPeerStatus, 100),
	}
	s.mcast, s.connect = stream.ToMulticast(stream.FromChannel(s.statusCh))
	return s
}

func (s *fakeBFDServer) Run(ctx context.Context) {
	s.connect(ctx)
}

func (s *fakeBFDServer) AddPeer(peer *types.BFDPeerConfig) error {
	s.generatePeerStatus(peer)
	return nil
}

func (s *fakeBFDServer) UpdatePeer(peer *types.BFDPeerConfig) error {
	s.generatePeerStatus(peer)
	return nil
}

func (s *fakeBFDServer) DeletePeer(peer *types.BFDPeerConfig) error {
	return nil
}

func (s *fakeBFDServer) Observe(ctx context.Context, next func(types.BFDPeerStatus), complete func(error)) {
	s.mcast.Observe(ctx, next, complete)
}

func (s *fakeBFDServer) generatePeerStatus(peer *types.BFDPeerConfig) {
	status := types.BFDPeerStatus{
		PeerAddress: peer.PeerAddress,
		Local: types.BFDSessionStatus{
			State:               types.BFDStateDown,
			ReceiveInterval:     peer.ReceiveInterval,
			TransmitInterval:    peer.TransmitInterval,
			EchoReceiveInterval: peer.EchoReceiveInterval,
			DetectMultiplier:    peer.DetectMultiplier,
		},
	}
	s.statusCh <- status
}

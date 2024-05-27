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
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging"
)

const (
	testTimeout = 5 * time.Second
)

func Test_BFDReconciler(t *testing.T) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	var (
		bfdPeerName      = "test-peer-1"
		bfdPeerIP        = netip.MustParseAddr("10.0.0.1")
		bfdPeerInterface = "eth0"

		bfdPeer2Name      = "test-peer-2"
		bfdPeer2IP        = netip.MustParseAddr("10.0.0.2")
		bfdPeer2Interface = "eth0"

		bfdProfileName  = "test-profile"
		bfdProfileSpec1 = v1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](10),
			TransmitIntervalMilliseconds: ptr.To[int32](20),
			DetectMultiplier:             ptr.To[int32](3),
			MinimumTTL:                   ptr.To[int32](255),
			EchoFunction: &v1alpha1.BFDEchoFunctionConfig{
				Directions: []v1alpha1.BFDEchoFunctionDirection{
					v1alpha1.BFDEchoFunctionDirectionReceive,
				},
				ReceiveIntervalMilliseconds: ptr.To[int32](5),
			},
		}
		bfdStatusProfile1 = types.BFDSessionStatus{
			State:               types.BFDStateDown,
			ReceiveInterval:     10 * time.Millisecond,
			TransmitInterval:    20 * time.Millisecond,
			DetectMultiplier:    3,
			EchoReceiveInterval: 5 * time.Millisecond,
		}

		bfdProfileSpec2 = v1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](11),
			TransmitIntervalMilliseconds: ptr.To[int32](21),
			DetectMultiplier:             ptr.To[int32](4),
			MinimumTTL:                   ptr.To[int32](255),
			EchoFunction: &v1alpha1.BFDEchoFunctionConfig{
				Directions: []v1alpha1.BFDEchoFunctionDirection{
					v1alpha1.BFDEchoFunctionDirectionReceive,
					v1alpha1.BFDEchoFunctionDirectionTransmit,
				},
				ReceiveIntervalMilliseconds:  ptr.To[int32](55),
				TransmitIntervalMilliseconds: ptr.To[int32](55),
			},
		}
		bfdStatusProfile2 = types.BFDSessionStatus{
			State:                types.BFDStateDown,
			ReceiveInterval:      11 * time.Millisecond,
			TransmitInterval:     21 * time.Millisecond,
			DetectMultiplier:     4,
			EchoReceiveInterval:  55 * time.Millisecond,
			EchoTransmitInterval: 55 * time.Millisecond,
		}

		bfdProfileSpecMultihop = v1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](11),
			TransmitIntervalMilliseconds: ptr.To[int32](21),
			DetectMultiplier:             ptr.To[int32](4),
			MinimumTTL:                   ptr.To[int32](200),
		}
		bfdStatusMultihop = types.BFDSessionStatus{
			State:            types.BFDStateDown,
			ReceiveInterval:  11 * time.Millisecond,
			TransmitInterval: 21 * time.Millisecond,
			DetectMultiplier: 4,
		}
	)

	var steps = []struct {
		description  string
		operation    string // "create" / "update" / "delete"
		bfdProfiles  []*v1alpha1.IsovalentBFDProfile
		nodeConfigs  []*v1alpha1.IsovalentBFDNodeConfig
		expectEvents []statedb.Change[*types.BFDPeerStatus]
	}{
		{
			description: "Add node config with missing profile",
			operation:   "create",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   bfdPeerIP.String(),
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectEvents: nil,
		},
		{
			description: "Add profile used in node config",
			operation:   "create",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpec1,
				},
			},
			nodeConfigs: nil,
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Update BFD profile - timer intervals",
			operation:   "update",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpec2,
				},
			},
			nodeConfigs: nil,
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile2,
					},
				},
			},
		},
		{
			description: "Update BFD profile - multihop - recreate",
			operation:   "update",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpecMultihop,
				},
			},
			nodeConfigs: nil,
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusMultihop,
					},
				},
			},
		},
		{
			description: "Delete BFD profile",
			operation:   "delete",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpecMultihop,
				},
			},
			nodeConfigs: nil,
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Deleted: true,
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusMultihop,
					},
				},
			},
		},
		{
			description: "Re-create BFD profile",
			operation:   "create",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpec1,
				},
			},
			nodeConfigs: nil,
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Update BFD node config - remove peer",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers:   []*v1alpha1.BFDNodePeerConfig{},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Deleted: true,
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Update BFD node config - add peer back",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   bfdPeerIP.String(),
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Update BFD node config - add 2nd peer",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   bfdPeerIP.String(),
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
							{
								Name:          bfdPeer2Name,
								PeerAddress:   bfdPeer2IP.String(),
								Interface:     ptr.To[string](bfdPeer2Interface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeer2IP,
						Interface:   bfdPeer2Interface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Update BFD node config - remove 2nd peer",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   bfdPeerIP.String(),
								Interface:     ptr.To[string](bfdPeer2Interface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Deleted: true,
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeer2IP,
						Interface:   bfdPeer2Interface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Update BFD node config - invalid NodeRef",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: "some-other-node",
						Peers:   []*v1alpha1.BFDNodePeerConfig{},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Deleted: true,
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Update BFD node config - correct NodeRef",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   bfdPeerIP.String(),
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Remove BFD node config",
			operation:   "delete",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers:   []*v1alpha1.BFDNodePeerConfig{},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Deleted: true,
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
		{
			description: "Create multiple conflicting node configs - best effort reconciliation",
			operation:   "create",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName + "-1",
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName + "-1",
								Interface:     ptr.To[string](bfdPeerInterface),
								PeerAddress:   bfdPeerIP.String(),
								BFDProfileRef: bfdProfileName,
							},
							{
								Name:          bfdPeerName + "-2",
								Interface:     ptr.To[string](bfdPeerInterface),
								PeerAddress:   bfdPeerIP.String(),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName + "-2",
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								Interface:     ptr.To[string](bfdPeerInterface),
								PeerAddress:   bfdPeerIP.String(),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectEvents: []statedb.Change[*types.BFDPeerStatus]{
				{
					Object: &types.BFDPeerStatus{
						PeerAddress: bfdPeerIP,
						Interface:   bfdPeerInterface,
						Local:       bfdStatusProfile1,
					},
				},
			},
		},
	}

	// create test fixture
	testCtx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(func() {
		cancel()
	})
	f, waitWatchersReady := newTestFixture(t, testCtx)

	// start the test hive
	log := hivetest.Logger(t)
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})

	// wait until the watchers are ready
	waitWatchersReady()

	observable := statedb.Observable[*types.BFDPeerStatus](f.db, f.peerTable)
	peersEventCh := stream.ToChannel(testCtx, observable)

	// run the test steps
	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			// CRUD BFD profiles
			for _, profile := range step.bfdProfiles {
				switch step.operation {
				case "create":
					_, err = f.profileClient.Create(testCtx, profile, metav1.CreateOptions{})
				case "update":
					_, err = f.profileClient.Update(testCtx, profile, metav1.UpdateOptions{})
				case "delete":
					err = f.profileClient.Delete(testCtx, profile.Name, metav1.DeleteOptions{})
				}
				require.NoError(t, err)
			}
			// CRUD BFD node configs
			for _, nc := range step.nodeConfigs {
				switch step.operation {
				case "create":
					_, err = f.ncClient.Create(testCtx, nc, metav1.CreateOptions{})
				case "update":
					_, err = f.ncClient.Update(testCtx, nc, metav1.UpdateOptions{})
				case "delete":
					err = f.ncClient.Delete(testCtx, nc.Name, metav1.DeleteOptions{})
				}
				require.NoError(t, err)
			}
			// validate events with the expected ones
			for _, expected := range step.expectEvents {
			nextEvent:
				select {
				case event := <-peersEventCh:
					if event.Object.Local.State == types.BFDStateAdminDown {
						// ignore initial events with AdminDown state,
						// created for a session that was not yet configured on the BFD server.
						goto nextEvent
					}
					validateEvents(t, expected, event)
				case <-testCtx.Done():
					t.Fatalf("missed expected event %+v", expected)
				}
			}
			// if no event is expected, validate there is none within a small time window
			if len(step.expectEvents) == 0 {
				timer := time.NewTimer(50 * time.Millisecond)
				select {
				case event := <-peersEventCh:
					t.Fatalf("unexpected event: %+v", event)
				case <-timer.C:
					// pass
				}
			}
		})
	}
}

func validateEvents(t *testing.T, expected, actual statedb.Change[*types.BFDPeerStatus]) {
	require.EqualValues(t, expected.Deleted, actual.Deleted)
	require.EqualValues(t, expected.Object.PeerAddress, actual.Object.PeerAddress)
	require.EqualValues(t, expected.Object.Interface, actual.Object.Interface)
	require.EqualValues(t, expected.Object.Local.State, actual.Object.Local.State)
	require.EqualValues(t, expected.Object.Local.ReceiveInterval, actual.Object.Local.ReceiveInterval)
	require.EqualValues(t, expected.Object.Local.TransmitInterval, actual.Object.Local.TransmitInterval)
	require.EqualValues(t, expected.Object.Local.EchoReceiveInterval, actual.Object.Local.EchoReceiveInterval)
	require.EqualValues(t, expected.Object.Local.DetectMultiplier, actual.Object.Local.DetectMultiplier)
}

func Test_detectEgressInterface(t *testing.T) {
	ifName, err := detectEgressInterface(netip.MustParseAddr("127.0.0.1"), netip.Addr{})
	require.NoError(t, err)
	require.NotEmpty(t, ifName)

	ifName, err = detectEgressInterface(netip.Addr{}, netip.MustParseAddr("1.2.3.4"))
	require.NoError(t, err)
	require.NotEmpty(t, ifName)

	ifName, err = detectEgressInterface(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("1.2.3.4"))
	require.NoError(t, err)
	require.NotEmpty(t, ifName)
}

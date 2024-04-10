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
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

func Test_ReconcileBGPNodeConfig(t *testing.T) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	var (
		node1Name   = "node-1"
		node2Name   = "node-2"
		node1Labels = map[string]string{"bgp": "rack1"}
		node2Labels = map[string]string{"bgp": "rack2"}
		ciliumNode1 = &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:   node1Name,
				Labels: node1Labels,
			},
		}
		ciliumNode2 = &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:   node2Name,
				Labels: node2Labels,
			},
		}

		bgpClusterConfig1Name = "bgp-cluster-config-1"
		bgpClusterConfig2Name = "bgp-cluster-config-2"

		peer1Addr = "172.1.0.1"
		peer2Addr = "172.2.0.1"

		bfdprofile1Name = "bfd-profile-1"
		bfdprofile2Name = "bfd-profile-2"

		bgpPeerConfigNoBFDProfile = &isovalentv1alpha1.IsovalentBGPPeerConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-no-bfd-profile"},
			Spec:       isovalentv1alpha1.IsovalentBGPPeerConfigSpec{},
		}
		bgpPeerConfigBFDProfile1 = &isovalentv1alpha1.IsovalentBGPPeerConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-bfd-profile-1"},
			Spec: isovalentv1alpha1.IsovalentBGPPeerConfigSpec{
				BFDProfileRef: ptr.To[string](bfdprofile1Name),
			},
		}
		bgpPeerConfigBFDProfile2 = &isovalentv1alpha1.IsovalentBGPPeerConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-bfd-profile-2"},
			Spec: isovalentv1alpha1.IsovalentBGPPeerConfigSpec{
				BFDProfileRef: ptr.To[string](bfdprofile2Name),
			},
		}
		bgpPeerConfigNoBFDProfileRef = &isovalentv1alpha1.PeerConfigReference{Name: bgpPeerConfigNoBFDProfile.Name}
		bgpPeerConfigBFDProfile1Ref  = &isovalentv1alpha1.PeerConfigReference{Name: bgpPeerConfigBFDProfile1.Name}
		bgpPeerConfigBFDProfile2Ref  = &isovalentv1alpha1.PeerConfigReference{Name: bgpPeerConfigBFDProfile2.Name}

		node1Interface             = "eth1"
		node1EchoSourceAddress     = "10.10.10.10"
		bfdNodeConfigOverrideNode1 = &isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
			ObjectMeta: metav1.ObjectMeta{Name: node1Name},
			Spec: isovalentv1alpha1.BFDNodeConfigOverrideSpec{
				Peers: []*isovalentv1alpha1.BFDNodeConfigOverridePeer{
					{
						PeerAddress:       peer1Addr,
						Interface:         &node1Interface,
						EchoSourceAddress: ptr.To[string](node1EchoSourceAddress),
					},
				},
			},
		}
	)

	steps := []struct {
		description            string
		nodes                  []*ciliumv2.CiliumNode
		deletedNodes           []*ciliumv2.CiliumNode
		bgpClusterConfigs      []*isovalentv1alpha1.IsovalentBGPClusterConfig
		bgpPeerConfigs         []*isovalentv1alpha1.IsovalentBGPPeerConfig
		bfdNodeConfigOverrides []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride
		expectedBFDNodeConfigs []*isovalentv1alpha1.IsovalentBFDNodeConfig
	}{
		{
			description: "one node, no BFD configured",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: nil,
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigNoBFDProfileRef,
									},
								},
							},
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigNoBFDProfileRef,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigNoBFDProfile,
			},
			expectedBFDNodeConfigs: nil,
		},
		{
			description: "one node, BFD configured for one peer",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: nil,
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
								},
							},
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigNoBFDProfileRef,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigBFDProfile1,
			},
			bfdNodeConfigOverrides: []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
				bfdNodeConfigOverrideNode1,
			},
			expectedBFDNodeConfigs: []*isovalentv1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node1Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node1Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:              getBFDPeerName(peer1Addr),
								PeerAddress:       peer1Addr,
								BFDProfileRef:     bfdprofile1Name,
								Interface:         &node1Interface,
								EchoSourceAddress: &node1EchoSourceAddress,
							},
						},
					},
				},
			},
		},
		{
			description: "one node, BFD configured for two peers",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: nil,
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
								},
							},
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile2Ref,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigBFDProfile1,
				bgpPeerConfigBFDProfile2,
			},
			bfdNodeConfigOverrides: []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
				bfdNodeConfigOverrideNode1,
			},
			expectedBFDNodeConfigs: []*isovalentv1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node1Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node1Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:              getBFDPeerName(peer1Addr),
								PeerAddress:       peer1Addr,
								BFDProfileRef:     bfdprofile1Name,
								Interface:         &node1Interface,
								EchoSourceAddress: &node1EchoSourceAddress,
							},
							{
								Name:          getBFDPeerName(peer2Addr),
								PeerAddress:   peer2Addr,
								BFDProfileRef: bfdprofile2Name,
							},
						},
					},
				},
			},
		},
		{
			description: "one node, BFD configured for two peers, same peers in multiple instances",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: nil,
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile2Ref,
									},
								},
							},
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile2Ref,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigBFDProfile1,
			},
			bfdNodeConfigOverrides: []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
				bfdNodeConfigOverrideNode1,
			},
			expectedBFDNodeConfigs: []*isovalentv1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node1Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node1Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:              getBFDPeerName(peer1Addr),
								PeerAddress:       peer1Addr,
								BFDProfileRef:     bfdprofile1Name,
								Interface:         &node1Interface,
								EchoSourceAddress: &node1EchoSourceAddress,
							},
							{
								Name:          getBFDPeerName(peer2Addr),
								PeerAddress:   peer2Addr,
								BFDProfileRef: bfdprofile2Name,
							},
						},
					},
				},
			},
		},
		{
			description: "two nodes, BFD configure for two peers",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
				ciliumNode2,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: nil,
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
								},
							},
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile2Ref,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigBFDProfile1,
				bgpPeerConfigBFDProfile2,
			},
			bfdNodeConfigOverrides: []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
				bfdNodeConfigOverrideNode1,
			},
			expectedBFDNodeConfigs: []*isovalentv1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node1Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node1Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:              getBFDPeerName(peer1Addr),
								PeerAddress:       peer1Addr,
								BFDProfileRef:     bfdprofile1Name,
								Interface:         &node1Interface,
								EchoSourceAddress: &node1EchoSourceAddress,
							},
							{
								Name:          getBFDPeerName(peer2Addr),
								PeerAddress:   peer2Addr,
								BFDProfileRef: bfdprofile2Name,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node2Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node2Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:          getBFDPeerName(peer1Addr),
								PeerAddress:   peer1Addr,
								BFDProfileRef: bfdprofile1Name,
							},
							{
								Name:          getBFDPeerName(peer2Addr),
								PeerAddress:   peer2Addr,
								BFDProfileRef: bfdprofile2Name,
							},
						},
					},
				},
			},
		},
		{
			description: "two nodes, only one selected by BGP cluster config, BFD configured for two peers",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
				ciliumNode2,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: node1Labels,
						},
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
								},
							},
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile2Ref,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigBFDProfile1,
				bgpPeerConfigBFDProfile2,
			},
			bfdNodeConfigOverrides: []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
				bfdNodeConfigOverrideNode1,
			},
			expectedBFDNodeConfigs: []*isovalentv1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node1Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node1Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:              getBFDPeerName(peer1Addr),
								PeerAddress:       peer1Addr,
								BFDProfileRef:     bfdprofile1Name,
								Interface:         &node1Interface,
								EchoSourceAddress: &node1EchoSourceAddress,
							},
							{
								Name:          getBFDPeerName(peer2Addr),
								PeerAddress:   peer2Addr,
								BFDProfileRef: bfdprofile2Name,
							},
						},
					},
				},
			},
		},
		{
			description: "two nodes, two BGP cluster configs, BFD configured for each peer",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
				ciliumNode2,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: node1Labels,
						},
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig2Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: node2Labels,
						},
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile2Ref,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigBFDProfile1,
				bgpPeerConfigBFDProfile2,
			},
			bfdNodeConfigOverrides: []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
				bfdNodeConfigOverrideNode1,
			},
			expectedBFDNodeConfigs: []*isovalentv1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node1Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node1Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:              getBFDPeerName(peer1Addr),
								PeerAddress:       peer1Addr,
								BFDProfileRef:     bfdprofile1Name,
								Interface:         &node1Interface,
								EchoSourceAddress: &node1EchoSourceAddress,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig2Name, node2Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node2Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:          getBFDPeerName(peer2Addr),
								PeerAddress:   peer2Addr,
								BFDProfileRef: bfdprofile2Name,
							},
						},
					},
				},
			},
		},
		{
			description: "one node deleted, two BGP cluster configs, BFD configured for each peer",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
			},
			deletedNodes: []*ciliumv2.CiliumNode{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   node2Name,
						Labels: node2Labels,
					},
				},
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: node1Labels,
						},
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile1Ref,
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig2Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: node2Labels,
						},
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigBFDProfile2Ref,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigBFDProfile1,
				bgpPeerConfigBFDProfile2,
			},
			bfdNodeConfigOverrides: []*isovalentv1alpha1.IsovalentBFDNodeConfigOverride{
				bfdNodeConfigOverrideNode1,
			},
			expectedBFDNodeConfigs: []*isovalentv1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: getNodeConfigName(bgpClusterConfig1Name, node1Name),
					},
					Spec: isovalentv1alpha1.BFDNodeConfigSpec{
						NodeRef: node1Name,
						Peers: []*isovalentv1alpha1.BFDNodePeerConfig{
							{
								Name:              getBFDPeerName(peer1Addr),
								PeerAddress:       peer1Addr,
								BFDProfileRef:     bfdprofile1Name,
								Interface:         &node1Interface,
								EchoSourceAddress: &node1EchoSourceAddress,
							},
						},
					},
				},
			},
		},
		{
			description: "one node, two BGP cluster configs, BFD disabled for peers",
			nodes: []*ciliumv2.CiliumNode{
				ciliumNode1,
			},
			bgpClusterConfigs: []*isovalentv1alpha1.IsovalentBGPClusterConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig1Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: node1Labels,
						},
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65000),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer1Addr,
										PeerConfigRef: bgpPeerConfigNoBFDProfileRef,
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bgpClusterConfig2Name,
					},
					Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: node2Labels,
						},
						BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
							{
								LocalASN: ptr.To[int64](65001),
								Peers: []isovalentv1alpha1.IsovalentBGPPeer{
									{
										PeerAddress:   &peer2Addr,
										PeerConfigRef: bgpPeerConfigNoBFDProfileRef,
									},
								},
							},
						},
					},
				},
			},
			bgpPeerConfigs: []*isovalentv1alpha1.IsovalentBGPPeerConfig{
				bgpPeerConfigNoBFDProfile,
			},
			expectedBFDNodeConfigs: nil,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	f, watchersReady := newFixture(ctx, require.New(t))

	log := hivetest.Logger(t)
	err := f.hive.Start(log, ctx)
	defer f.hive.Stop(log, ctx)
	require.NoError(t, err)

	watchersReady()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			req := require.New(t)

			// setup nodes
			for _, node := range step.nodes {
				upsertNode(req, ctx, f, node)
			}
			for _, node := range step.deletedNodes {
				deleteNode(req, ctx, f, node)
			}

			// upsert BGP cluster configs
			for _, cc := range step.bgpClusterConfigs {
				upsertBGPClusterConfig(req, ctx, f, cc)
			}

			// upsert BGP peer configs
			for _, pc := range step.bgpPeerConfigs {
				upsertBGPPeerConfig(req, ctx, f, pc)
			}

			// upsert BFD node config overrides
			for _, pc := range step.bfdNodeConfigOverrides {
				upsertBFDNodeConfigOverrides(req, ctx, f, pc)
			}

			// validate node configs
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				nodeConfigs, err := f.bfdNodeConfigClient.List(ctx, metav1.ListOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}
				assert.Equal(c, len(step.expectedBFDNodeConfigs), len(nodeConfigs.Items))

				for _, expectedNodeConfig := range step.expectedBFDNodeConfigs {
					nodeConfig, err := f.bfdNodeConfigClient.Get(ctx, expectedNodeConfig.Name, metav1.GetOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, expectedNodeConfig.Name, nodeConfig.Name)
					assert.Equal(c, expectedNodeConfig.Spec, nodeConfig.Spec)
				}
			}, TestTimeout, 50*time.Millisecond)
		})
	}
}

func upsertNode(req *require.Assertions, ctx context.Context, f *fixture, node *ciliumv2.CiliumNode) {
	_, err := f.ciliumNodeClient.Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.ciliumNodeClient.Create(ctx, node, metav1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.ciliumNodeClient.Update(ctx, node, metav1.UpdateOptions{})
	}
	req.NoError(err)
}

func deleteNode(req *require.Assertions, ctx context.Context, f *fixture, node *ciliumv2.CiliumNode) {
	err := f.ciliumNodeClient.Delete(ctx, node.Name, metav1.DeleteOptions{})
	req.NoError(err)
}

func upsertBGPPeerConfig(req *require.Assertions, ctx context.Context, f *fixture, pc *isovalentv1alpha1.IsovalentBGPPeerConfig) {
	_, err := f.bgpPeerConfigClient.Get(ctx, pc.Name, metav1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.bgpPeerConfigClient.Create(ctx, pc, metav1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.bgpPeerConfigClient.Update(ctx, pc, metav1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertBGPClusterConfig(req *require.Assertions, ctx context.Context, f *fixture, cc *isovalentv1alpha1.IsovalentBGPClusterConfig) {
	_, err := f.bgpClusterConfigClient.Get(ctx, cc.Name, metav1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.bgpClusterConfigClient.Create(ctx, cc, metav1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.bgpClusterConfigClient.Update(ctx, cc, metav1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertBFDNodeConfigOverrides(req *require.Assertions, ctx context.Context, f *fixture, o *isovalentv1alpha1.IsovalentBFDNodeConfigOverride) {
	_, err := f.bfdNodeConfigOverrideClient.Get(ctx, o.Name, metav1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.bfdNodeConfigOverrideClient.Create(ctx, o, metav1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.bfdNodeConfigOverrideClient.Update(ctx, o, metav1.UpdateOptions{})
	}
	req.NoError(err)
}

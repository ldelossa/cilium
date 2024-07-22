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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	advertTestLogger = logrus.WithField("unit_test", "advertisement")
)

var (
	podCIDRLabel = map[string]string{
		"advertise": "pod_cidr",
	}

	podCIDRAdvert = &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "podCIDR-advertisement",
			Labels: podCIDRLabel,
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{
				{
					AdvertisementType: v1alpha1.BGPPodCIDRAdvert,
				},
			},
		},
	}

	basePeerConfig = &v1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config",
		},
		Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: v2alpha1.CiliumBGPPeerConfigSpec{
				Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
					},
				},
			},
		},
	}

	baseVRFConfig = &v1alpha1.IsovalentBGPVRFConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vrf-config",
		},
		Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
				},
			},
		},
	}

	baseVRFConfigWithAdvertLabels = func(advertLabels map[string]string) *v1alpha1.IsovalentBGPVRFConfig {
		vrfConfig := baseVRFConfig.DeepCopy()
		for i := range vrfConfig.Spec.Families {
			vrfConfig.Spec.Families[i].Advertisements = slim_metav1.SetAsLabelSelector(advertLabels)
		}

		return vrfConfig
	}

	peerConfigWithAdvertLabels = func(advertLabels map[string]string) *v1alpha1.IsovalentBGPPeerConfig {
		peerConfig := basePeerConfig.DeepCopy()
		for i := range peerConfig.Spec.Families {
			peerConfig.Spec.Families[i].Advertisements = slim_metav1.SetAsLabelSelector(advertLabels)
		}

		return peerConfig
	}
)

func TestPeerAdvertisements(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                string
		peerConfig          *v1alpha1.IsovalentBGPPeerConfig
		advertisement       *v1alpha1.IsovalentBGPAdvertisement
		reqAdvertType       v1alpha1.IsovalentBGPAdvertType
		reqBGPNodeInstance  *v1alpha1.IsovalentBGPNodeInstance
		expectedPeerAdverts PeerAdvertisements
	}{
		{
			name:          "No result, peer config not found",
			peerConfig:    nil,
			advertisement: podCIDRAdvert,
			reqAdvertType: v1alpha1.BGPPodCIDRAdvert,
			reqBGPNodeInstance: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1alpha1.IsovalentBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v1alpha1.PeerConfigReference{
							Name: "peer-config",
						},
					},
				},
			},
			expectedPeerAdverts: make(PeerAdvertisements),
		},
		{
			name:          "No result, peer config found but advertisement labels don't match",
			peerConfig:    basePeerConfig,
			advertisement: podCIDRAdvert,
			reqAdvertType: v1alpha1.BGPPodCIDRAdvert,
			reqBGPNodeInstance: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1alpha1.IsovalentBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v1alpha1.PeerConfigReference{
							Name: "peer-config",
						},
					},
				},
			},
			expectedPeerAdverts: PeerAdvertisements{
				"red-peer-65001": map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: nil,
				},
			},
		},
		{
			name:          "Valid result, peer config found with matching advertisement",
			peerConfig:    peerConfigWithAdvertLabels(podCIDRLabel),
			advertisement: podCIDRAdvert,
			reqAdvertType: v1alpha1.BGPPodCIDRAdvert,
			reqBGPNodeInstance: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1alpha1.IsovalentBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v1alpha1.PeerConfigReference{
							Name: "peer-config",
						},
					},
				},
			},
			expectedPeerAdverts: PeerAdvertisements{
				"red-peer-65001": map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {v1alpha1.BGPAdvertisement{
						AdvertisementType: v1alpha1.BGPPodCIDRAdvert,
					}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			isoAdvert := &IsovalentAdvertisement{
				logger:     advertTestLogger,
				peerConfig: newMockResourceStore[*v1alpha1.IsovalentBGPPeerConfig](),
				adverts:    newMockResourceStore[*v1alpha1.IsovalentBGPAdvertisement](),
			}

			if tt.peerConfig != nil {
				isoAdvert.peerConfig = InitMockStore[*v1alpha1.IsovalentBGPPeerConfig]([]*v1alpha1.IsovalentBGPPeerConfig{tt.peerConfig})
			}

			if tt.advertisement != nil {
				isoAdvert.adverts = InitMockStore[*v1alpha1.IsovalentBGPAdvertisement]([]*v1alpha1.IsovalentBGPAdvertisement{tt.advertisement})
			}

			// Initialize the advertisement reconciler
			isoAdvert.initialized.Store(true)

			reconciledPeerAdverts, err := isoAdvert.GetConfiguredPeerAdvertisements(tt.reqBGPNodeInstance, tt.reqAdvertType)
			req.NoError(err)
			req.Equal(tt.expectedPeerAdverts, reconciledPeerAdverts)
		})
	}
}

func TestVRFAdvertisements(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name               string
		vrfConfig          *v1alpha1.IsovalentBGPVRFConfig
		advertisement      *v1alpha1.IsovalentBGPAdvertisement
		reqAdvertType      v1alpha1.IsovalentBGPAdvertType
		reqBGPNodeInstance *v1alpha1.IsovalentBGPNodeInstance
		expectedVRFAdverts VRFAdvertisements
	}{
		{
			name:          "No result, vrf config not found",
			vrfConfig:     nil,
			advertisement: podCIDRAdvert,
			reqAdvertType: v1alpha1.BGPPodCIDRAdvert,
			reqBGPNodeInstance: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				VRFs: []v1alpha1.IsovalentBGPNodeVRF{
					{
						VRFRef:    "vrf-1",
						ConfigRef: ptr.To[string]("vrf-config"),
						RD:        ptr.To[string]("65001:1"),
					},
				},
			},
			expectedVRFAdverts: make(VRFAdvertisements),
		},
		{
			name:          "No result, vrf config found but advertisement labels don't match",
			vrfConfig:     baseVRFConfig,
			advertisement: podCIDRAdvert,
			reqAdvertType: v1alpha1.BGPPodCIDRAdvert,
			reqBGPNodeInstance: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				VRFs: []v1alpha1.IsovalentBGPNodeVRF{
					{
						VRFRef:    "vrf-1",
						ConfigRef: ptr.To[string]("vrf-config"),
						RD:        ptr.To[string]("65001:1"),
					},
				},
			},
			expectedVRFAdverts: VRFAdvertisements{
				"vrf-1": map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "mpls_vpn"}: nil,
				},
			},
		},
		{
			name:          "Valid result, vrf config found with matching advertisement",
			vrfConfig:     baseVRFConfigWithAdvertLabels(podCIDRLabel),
			advertisement: podCIDRAdvert,
			reqAdvertType: v1alpha1.BGPPodCIDRAdvert,
			reqBGPNodeInstance: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				VRFs: []v1alpha1.IsovalentBGPNodeVRF{
					{
						VRFRef:    "vrf-1",
						ConfigRef: ptr.To[string]("vrf-config"),
						RD:        ptr.To[string]("65001:1"),
					},
				},
			},
			expectedVRFAdverts: VRFAdvertisements{
				"vrf-1": map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "mpls_vpn"}: {v1alpha1.BGPAdvertisement{
						AdvertisementType: v1alpha1.BGPPodCIDRAdvert,
					}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			isoAdvert := &IsovalentAdvertisement{
				logger:  advertTestLogger,
				adverts: newMockResourceStore[*v1alpha1.IsovalentBGPAdvertisement](),
				vrfs:    store.NewMockBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig](),
			}

			if tt.advertisement != nil {
				isoAdvert.adverts = InitMockStore[*v1alpha1.IsovalentBGPAdvertisement]([]*v1alpha1.IsovalentBGPAdvertisement{tt.advertisement})
			}

			if tt.vrfConfig != nil {
				isoAdvert.vrfs = store.InitMockStore[*v1alpha1.IsovalentBGPVRFConfig]([]*v1alpha1.IsovalentBGPVRFConfig{tt.vrfConfig})
			}

			// Initialize the advertisement reconciler
			isoAdvert.initialized.Store(true)

			reconciledVRFAdverts, err := isoAdvert.GetConfiguredVRFAdvertisements(tt.reqBGPNodeInstance, tt.reqAdvertType)
			req.NoError(err)
			req.Equal(tt.expectedVRFAdverts, reconciledVRFAdverts)
		})
	}
}

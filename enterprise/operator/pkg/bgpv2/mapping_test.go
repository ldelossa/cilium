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
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

var (
	isoClusterConfig = &v1alpha1.IsovalentBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "test-bgp-cluster-config",
			Labels: map[string]string{
				"bgp": "dummy_label",
			},
			ResourceVersion: "1234",
		},
		Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"bgp": "rack1",
				},
			},
			BGPInstances: []v1alpha1.IsovalentBGPInstance{
				{
					Name:     "instance-1",
					LocalASN: ptr.To[int64](65001),
					Peers: []v1alpha1.IsovalentBGPPeer{
						{
							Name:        "peer-1",
							PeerAddress: ptr.To[string]("192.168.10.10"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v1alpha1.PeerConfigReference{
								Name: "peer-config-1",
							},
						},
						{
							Name:        "peer-2",
							PeerAddress: ptr.To[string]("192.168.10.20"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v1alpha1.PeerConfigReference{
								Name: "peer-config-2",
							},
						},
					},
				},
			},
		},
	}
	isoNodeConfigSpec = v1alpha1.IsovalentBGPNodeInstance{
		Name:     "instance-1",
		LocalASN: ptr.To[int64](65001),
		Peers: []v1alpha1.IsovalentBGPNodePeer{
			{
				Name:        "peer-1",
				PeerAddress: ptr.To[string]("192.168.10.10"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v1alpha1.PeerConfigReference{
					Name: "peer-config-1",
				},
			},
			{
				Name:        "peer-2",
				PeerAddress: ptr.To[string]("192.168.10.20"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v1alpha1.PeerConfigReference{
					Name: "peer-config-2",
				},
			},
		},
	}
	isoNodeConfigSpecWithResponder = func() v1alpha1.IsovalentBGPNodeInstance {
		cpy := isoNodeConfigSpec.DeepCopy()
		cpy.SRv6Responder = ptr.To[bool](true)
		return *cpy
	}

	ossClusterConfig = &v2alpha1.CiliumBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "test-bgp-cluster-config",
			Labels: map[string]string{
				"bgp": "dummy_label",
			},
		},
		Spec: v2alpha1.CiliumBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"bgp": "rack1",
				},
			},
			BGPInstances: []v2alpha1.CiliumBGPInstance{
				{
					Name:     "instance-1",
					LocalASN: ptr.To[int64](65001),
					Peers: []v2alpha1.CiliumBGPPeer{
						{
							Name:        "peer-1",
							PeerAddress: ptr.To[string]("192.168.10.10"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v2alpha1.PeerConfigReference{
								Name: "peer-config-1",
							},
						},
						{
							Name:        "peer-2",
							PeerAddress: ptr.To[string]("192.168.10.20"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v2alpha1.PeerConfigReference{
								Name: "peer-config-2",
							},
						},
					},
				},
			},
		},
	}
	ossPeerConfigSpec = v2alpha1.CiliumBGPPeerConfigSpec{
		Transport: &v2alpha1.CiliumBGPTransport{
			LocalPort: ptr.To[int32](179),
			PeerPort:  ptr.To[int32](179),
		},
		Timers: &v2alpha1.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](12),
			HoldTimeSeconds:         ptr.To[int32](9),
			KeepAliveTimeSeconds:    ptr.To[int32](3),
		},
		AuthSecretRef: ptr.To[string]("bgp-secret"),
		GracefulRestart: &v2alpha1.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](12),
		},
		Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Advertisements: &slimv1.LabelSelector{
					MatchLabels: map[string]slimv1.MatchLabelsValue{
						"bgp": "advert-1",
					},
				},
			},
		},
	}
	isoPeerConfig = &v1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "peer-config-1",
			Labels: map[string]string{
				"bgp": "dummy_label_1",
			},
			ResourceVersion: "2345",
		},
		Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: ossPeerConfigSpec,
		},
	}
	ossPeerConfig = &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "peer-config-1",
			Labels: map[string]string{
				"bgp": "dummy_label_1",
			},
		},
		Spec: ossPeerConfigSpec,
	}
	isoAdvertPodCIDR = &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-pod-cidr",
			Labels: map[string]string{
				"bgp": "advert-1",
			},
			ResourceVersion: "3456",
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{
				{
					AdvertisementType: "PodCIDR",
					Attributes: &v2alpha1.BGPAttributes{
						LocalPreference: ptr.To[int64](99),
					},
				},
				{
					AdvertisementType: "EgressGateway", // should be ignored by mapper
					Attributes: &v2alpha1.BGPAttributes{
						LocalPreference: ptr.To[int64](100),
					},
				},
			},
		},
	}
	ossAdvertPodCIDR = &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-pod-cidr",
			Labels: map[string]string{
				"bgp": "advert-1",
			},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{
				{
					AdvertisementType: "PodCIDR",
					Attributes: &v2alpha1.BGPAttributes{
						LocalPreference: ptr.To[int64](99),
					},
				},
			},
		},
	}
	isoAdvertIPPool = &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-ip-pool",
			Labels: map[string]string{
				"bgp": "advert-2",
			},
			ResourceVersion: "4567",
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{
				{
					AdvertisementType: "CiliumPodIPPool",
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"pool": "blue",
						},
					},
					Attributes: &v2alpha1.BGPAttributes{
						LocalPreference: ptr.To[int64](101),
					},
				},
			},
		},
	}
	ossAdvertIPPool = &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-ip-pool",
			Labels: map[string]string{
				"bgp": "advert-2",
			},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{
				{
					AdvertisementType: "CiliumPodIPPool",
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"pool": "blue",
						},
					},
					Attributes: &v2alpha1.BGPAttributes{
						LocalPreference: ptr.To[int64](101),
					},
				},
			},
		},
	}
	isoAdvertService = &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-service",
			Labels: map[string]string{
				"bgp": "advert-3",
			},
			ResourceVersion: "5678",
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{
				{
					AdvertisementType: "Service",
					Service: &v1alpha1.BGPServiceOptions{
						Addresses: []v2alpha1.BGPServiceAddressType{
							v2alpha1.BGPLoadBalancerIPAddr,
							v2alpha1.BGPClusterIPAddr,
							v2alpha1.BGPExternalIPAddr,
						},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"service": "nginx",
						},
					},
					Attributes: &v2alpha1.BGPAttributes{
						LocalPreference: ptr.To[int64](102),
					},
				},
			},
		},
	}
	ossAdvertService = &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-service",
			Labels: map[string]string{
				"bgp": "advert-3",
			},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{
				{
					AdvertisementType: "Service",
					Service: &v2alpha1.BGPServiceOptions{
						Addresses: []v2alpha1.BGPServiceAddressType{
							v2alpha1.BGPLoadBalancerIPAddr,
							v2alpha1.BGPClusterIPAddr,
							v2alpha1.BGPExternalIPAddr,
						},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"service": "nginx",
						},
					},
					Attributes: &v2alpha1.BGPAttributes{
						LocalPreference: ptr.To[int64](102),
					},
				},
			},
		},
	}
)

func Test_Mapping(t *testing.T) {
	tests := []struct {
		description              string
		isoClusterConfig         *v1alpha1.IsovalentBGPClusterConfig
		isoPeerConfig            *v1alpha1.IsovalentBGPPeerConfig
		isoAdvert                *v1alpha1.IsovalentBGPAdvertisement
		isoNodeConfigOR          *v1alpha1.IsovalentBGPNodeConfigOverride
		expectedOSSClusterConfig *v2alpha1.CiliumBGPClusterConfig
		expectedOSSPeerConfig    *v2alpha1.CiliumBGPPeerConfig
		expectedOSSAdvert        *v2alpha1.CiliumBGPAdvertisement
		expectedOSSNodeConfigOR  *v2alpha1.CiliumBGPNodeConfigOverride
	}{
		{
			description:              "test cluster config mapping",
			isoClusterConfig:         isoClusterConfig,
			expectedOSSClusterConfig: ossClusterConfig,
		},
		{
			description:           "test peer config mapping",
			isoPeerConfig:         isoPeerConfig,
			expectedOSSPeerConfig: ossPeerConfig,
		},
		{
			description:       "test bgp advertisement - pod cidr",
			isoAdvert:         isoAdvertPodCIDR,
			expectedOSSAdvert: ossAdvertPodCIDR,
		},
		{
			description:       "test bgp advertisement - pod IP pool",
			isoAdvert:         isoAdvertIPPool,
			expectedOSSAdvert: ossAdvertIPPool,
		},
		{
			description:       "test bgp advertisement - service",
			isoAdvert:         isoAdvertService,
			expectedOSSAdvert: ossAdvertService,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := require.New(t)
			f, watcherReady := newFixture(ctx, req)

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			// blocking till all watchers are ready
			watcherReady()

			// insert enterprise objects
			upsertIsoBGPCC(req, ctx, f, tt.isoClusterConfig)
			upsertIsoBGPPC(req, ctx, f, tt.isoPeerConfig)
			upsertIsoBGPAdvert(req, ctx, f, tt.isoAdvert)
			upsertIsoBGPNodeConfigOR(req, ctx, f, tt.isoNodeConfigOR)

			// check OSS objects are created as expected
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoClusterConfig == nil {
					clusterConfigs, err := f.ossClusterClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, 0, len(clusterConfigs.Items))
					return
				}

				ossClusterConfig, err := f.ossClusterClient.Get(ctx, tt.isoClusterConfig.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, tt.expectedOSSClusterConfig.Name, ossClusterConfig.Name)
				assert.Equal(c, tt.expectedOSSClusterConfig.Labels, ossClusterConfig.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: tt.isoClusterConfig.ResourceVersion}, ossClusterConfig.Annotations)
				assert.True(c, tt.expectedOSSClusterConfig.Spec.DeepEqual(&tt.expectedOSSClusterConfig.Spec))
			}, TestTimeout, 50*time.Millisecond)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoPeerConfig == nil {
					peerConfigs, err := f.ossPeerConfClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, 0, len(peerConfigs.Items))
					return
				}

				ossPeerConfig, err := f.ossPeerConfClient.Get(ctx, tt.isoPeerConfig.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, tt.expectedOSSPeerConfig.Name, ossPeerConfig.Name)
				assert.Equal(c, tt.expectedOSSPeerConfig.Labels, ossPeerConfig.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: tt.isoPeerConfig.ResourceVersion}, ossPeerConfig.Annotations)
				assert.True(c, tt.expectedOSSPeerConfig.Spec.DeepEqual(&tt.expectedOSSPeerConfig.Spec))
			}, TestTimeout, 50*time.Millisecond)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoAdvert == nil {
					ossAdverts, err := f.ossAdvertClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, 0, len(ossAdverts.Items))
					return
				}

				ossAdvert, err := f.ossAdvertClient.Get(ctx, tt.isoAdvert.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, tt.expectedOSSAdvert.Name, ossAdvert.Name)
				assert.Equal(c, tt.expectedOSSAdvert.Labels, ossAdvert.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: tt.isoAdvert.ResourceVersion}, ossAdvert.Annotations)
				assert.True(c, tt.expectedOSSAdvert.Spec.DeepEqual(&tt.expectedOSSAdvert.Spec))
			}, TestTimeout, 50*time.Millisecond)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoNodeConfigOR == nil {
					ossNodeConfigs, err := f.ossNodeConfORClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, 0, len(ossNodeConfigs.Items))
					return
				}

				ossNodeConfigOR, err := f.ossNodeConfORClient.Get(ctx, tt.isoNodeConfigOR.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, tt.expectedOSSNodeConfigOR.Name, ossNodeConfigOR.Name)
				assert.Equal(c, tt.expectedOSSNodeConfigOR.Labels, ossNodeConfigOR.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: tt.isoNodeConfigOR.ResourceVersion}, ossNodeConfigOR.Annotations)
				assert.True(c, tt.expectedOSSNodeConfigOR.Spec.DeepEqual(&tt.expectedOSSNodeConfigOR.Spec))
			}, TestTimeout, 50*time.Millisecond)
		})
	}
}

func upsertIsoBGPCC(req *require.Assertions, ctx context.Context, f *fixture, bgpcc *v1alpha1.IsovalentBGPClusterConfig) {
	if bgpcc == nil {
		return
	}

	_, err := f.isoClusterClient.Get(ctx, bgpcc.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoClusterClient.Create(ctx, bgpcc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.isoClusterClient.Update(ctx, bgpcc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPPC(req *require.Assertions, ctx context.Context, f *fixture, bgppc *v1alpha1.IsovalentBGPPeerConfig) {
	if bgppc == nil {
		return
	}

	_, err := f.isoPeerConfClient.Get(ctx, bgppc.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoPeerConfClient.Create(ctx, bgppc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.isoPeerConfClient.Update(ctx, bgppc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPAdvert(req *require.Assertions, ctx context.Context, f *fixture, bgpAdvert *v1alpha1.IsovalentBGPAdvertisement) {
	if bgpAdvert == nil {
		return
	}

	_, err := f.isoAdvertClient.Get(ctx, bgpAdvert.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoAdvertClient.Create(ctx, bgpAdvert, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.isoAdvertClient.Update(ctx, bgpAdvert, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPNodeConfigOR(req *require.Assertions, ctx context.Context, f *fixture, bgpNodeConfigOR *v1alpha1.IsovalentBGPNodeConfigOverride) {
	if bgpNodeConfigOR == nil {
		return
	}

	_, err := f.isoBGPNodeConfORClient.Get(ctx, bgpNodeConfigOR.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoBGPNodeConfORClient.Create(ctx, bgpNodeConfigOR, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.isoBGPNodeConfORClient.Update(ctx, bgpNodeConfigOR, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

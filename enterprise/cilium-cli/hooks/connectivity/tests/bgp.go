// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"fmt"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const (
	bgpAdvertisementName = "test-bgp-advertisement"
	bgpPeerConfigName    = "test-bgp-peer-config"
	bgpClusterConfigName = "test-bgp-cluster-config"

	bgpCiliumASN = 65001
	bgpFRRASN    = 65000

	bgpCommunityPodCIDR = "65001:100"
	bgpCommunityService = "65001:200"
)

func BGPSvcAdvertisements() check.Scenario {
	return &bgpSvcAdvertisements{}
}

type bgpSvcAdvertisements struct{}

func (s *bgpSvcAdvertisements) Name() string {
	return "bgp-svc-advertisements"
}

func (s *bgpSvcAdvertisements) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	t.ForEachIPFamily(func(ipFamily features.IPFamily) {
		defer func() {
			s.cleanup(ctx, t)
		}()

		// configure FRR
		frrPeers := ct.InternalNodeIPAddresses(ipFamily)
		frrConfig := check.RenderFRRBGPPeeringConfig(t, check.FRRBGPPeeringParams{
			LocalASN: bgpFRRASN,
			Peers:    frrPeers,
		})
		for _, frr := range ct.FRRPods() {
			check.ApplyFRRConfig(ctx, t, &frr, frrConfig)
		}

		// configure BGP on Cilium
		configureBGPPeering(ctx, t, ipFamily, "")

		// wait for BGP peers and expected prefixes
		podCIDRPrefixes := ct.PodCIDRPrefixes(ipFamily)
		svcPrefixes := ct.EchoServicePrefixes(ipFamily)
		for _, frr := range ct.FRRPods() {
			check.WaitForFRRBGPNeighborsState(ctx, t, &frr, frrPeers, "Established")

			frrPrefixes := check.WaitForFRRBGPPrefixes(ctx, t, &frr, podCIDRPrefixes, ipFamily)
			check.AssertFRRBGPCommunity(t, frrPrefixes, podCIDRPrefixes, bgpCommunityPodCIDR)

			frrPrefixes = check.WaitForFRRBGPPrefixes(ctx, t, &frr, svcPrefixes, ipFamily)
			check.AssertFRRBGPCommunity(t, frrPrefixes, svcPrefixes, bgpCommunityService)
		}

		for _, client := range ct.ExternalEchoPods() {
			// curl from external echo pods to in-cluster echo pods
			i := 0
			for _, echo := range ct.EchoPods() {
				t.NewAction(s, fmt.Sprintf("curl-echo-pod-%s-%d", ipFamily, i), &client, echo, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, ipFamily))
				})
				i++
			}
			//  curl from external echo pods to ClusterIP service IPs
			i = 0
			if status, ok := ct.Feature(features.BPFLBExternalClusterIP); ok && status.Enabled {
				for _, echo := range ct.EchoServices() {
					t.NewAction(s, fmt.Sprintf("curl-echo-service-%s-%d", ipFamily, i), &client, echo, ipFamily).Run(func(a *check.Action) {
						a.ExecInPod(ctx, ct.CurlCommand(echo, ipFamily))
					})
					i++
				}
			}
		}
	})
}

func (s *bgpSvcAdvertisements) cleanup(ctx context.Context, t *check.Test) {
	if t.Failed() {
		for _, frr := range t.Context().FRRPods() {
			check.DumpFRRBGPState(ctx, t, &frr)
		}
	}

	// delete test-configured K8s resources
	deleteBGPPeeringResources(ctx, t)

	// clear FRR config
	for _, frr := range t.Context().FRRPods() {
		check.ClearFRRConfig(ctx, t, &frr)
	}
}

func configureBGPPeering(ctx context.Context, t *check.Test, ipFamily features.IPFamily, bfdProfile string) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.IsovalentV1alpha1()
	deleteBGPPeeringResources(ctx, t)

	// configure advertisement
	advertisement := &isovalentv1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   bgpAdvertisementName,
			Labels: map[string]string{"test": "bgp"},
		},
		Spec: isovalentv1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []isovalentv1alpha1.BGPAdvertisement{
				{
					AdvertisementType: isovalentv1alpha1.BGPPodCIDRAdvert,
					Attributes: &ciliumv2alpha1.BGPAttributes{
						Communities: &ciliumv2alpha1.BGPCommunities{
							Standard: []ciliumv2alpha1.BGPStandardCommunity{bgpCommunityPodCIDR},
						},
					},
				},
				{
					AdvertisementType: isovalentv1alpha1.BGPServiceAdvert,
					Service: &ciliumv2alpha1.BGPServiceOptions{
						Addresses: []ciliumv2alpha1.BGPServiceAddressType{ciliumv2alpha1.BGPClusterIPAddr},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{"kind": "echo"},
					},
					Attributes: &ciliumv2alpha1.BGPAttributes{
						Communities: &ciliumv2alpha1.BGPCommunities{
							Standard: []ciliumv2alpha1.BGPStandardCommunity{bgpCommunityService},
						},
					},
				},
			},
		},
	}
	_, err := client.IsovalentBGPAdvertisements().Create(ctx, advertisement, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPAdvertisement: %v", err)
	}

	// configure peer config
	peerConfig := &isovalentv1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPeerConfigName,
		},
		Spec: isovalentv1alpha1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: ciliumv2alpha1.CiliumBGPPeerConfigSpec{
				Timers: &ciliumv2alpha1.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To[int32](1),
					KeepAliveTimeSeconds:    ptr.To[int32](1),
					HoldTimeSeconds:         ptr.To[int32](3),
				},
				Families: []ciliumv2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: ciliumv2alpha1.CiliumBGPFamily{
							Afi:  ipFamily.String(),
							Safi: "unicast",
						},
						Advertisements: &slimv1.LabelSelector{
							MatchLabels: advertisement.Labels,
						},
					},
				},
			},
		},
	}
	if bfdProfile != "" {
		peerConfig.Spec.BFDProfileRef = &bfdProfile
	}
	_, err = client.IsovalentBGPPeerConfigs().Create(ctx, peerConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPPeerConfig: %v", err)
	}

	// configure cluster config
	clusterConfig := &isovalentv1alpha1.IsovalentBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpClusterConfigName,
		},
		Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
			BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
				{
					Name:     "test-instance",
					LocalASN: ptr.To[int64](bgpCiliumASN),
				},
			},
		},
	}
	for _, frr := range ct.FRRPods() {
		clusterConfig.Spec.BGPInstances[0].Peers = append(clusterConfig.Spec.BGPInstances[0].Peers,
			isovalentv1alpha1.IsovalentBGPPeer{
				Name:        "peer-" + frr.Address(ipFamily),
				PeerAddress: ptr.To[string](frr.Address(ipFamily)),
				PeerASN:     ptr.To[int64](bgpFRRASN),
				PeerConfigRef: &isovalentv1alpha1.PeerConfigReference{
					Name: peerConfig.Name,
				},
			})
	}
	_, err = client.IsovalentBGPClusterConfigs().Create(ctx, clusterConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPClusterConfig: %v", err)
	}
}

func deleteBGPPeeringResources(ctx context.Context, t *check.Test) {
	client := t.Context().K8sClient().CiliumClientset.IsovalentV1alpha1()

	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPClusterConfigs(), bgpClusterConfigName)
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPPeerConfigs(), bgpPeerConfigName)
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPAdvertisements(), bgpAdvertisementName)
}

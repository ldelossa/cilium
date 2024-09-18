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
	"errors"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

const (
	// ownerVersionAnnotation is used to track the last reconciled version of the owner (parent) CRD object
	ownerVersionAnnotation = annotation.ConfigPrefix + "/owner-version"
)

func (m *BGPResourceMapper) reconcileMappings(ctx context.Context) error {
	// we try to reconcile all resources, even if some fail. Since each resource is independent,
	// we can continue with the next resource if one fails.

	err := m.mapClusterConfigs(ctx)
	err = errors.Join(err, m.mapPeerConfigs(ctx))
	err = errors.Join(err, m.mapAdvertisements(ctx))
	err = errors.Join(err, m.mapNodeConfigOverrides(ctx))
	return err
}

func (m *BGPResourceMapper) mapClusterConfigs(ctx context.Context) error {
	entClusterConfigs, err := m.clusterConfig.List()
	if err != nil {
		return err
	}

	for _, entClusterConfig := range entClusterConfigs {
		err = errors.Join(err, m.mapClusterConfig(ctx, entClusterConfig))
	}
	return err
}

func (m *BGPResourceMapper) mapClusterConfig(ctx context.Context, entClusterConfig *v1alpha1.IsovalentBGPClusterConfig) error {
	expectedOSSClusterConfig := createOSSClusterConfig(entClusterConfig)
	runningOSSClusterConfig, exists, err := m.ossClusterConfigStore.GetByKey(resource.Key{
		Name:      entClusterConfig.GetName(),
		Namespace: entClusterConfig.GetNamespace(),
	})
	if err != nil {
		return err
	}

	clusterConfigClientSet := m.clientSet.CiliumV2alpha1().CiliumBGPClusterConfigs()

	switch {
	case exists && expectedOSSClusterConfig.Spec.DeepEqual(&runningOSSClusterConfig.Spec) &&
		maps.Equal(expectedOSSClusterConfig.Labels, runningOSSClusterConfig.Labels) &&
		maps.Equal(expectedOSSClusterConfig.Annotations, runningOSSClusterConfig.Annotations):
		return nil

	case exists:
		// update
		runningOSSClusterConfig.Spec = expectedOSSClusterConfig.Spec
		runningOSSClusterConfig.Labels = expectedOSSClusterConfig.Labels
		runningOSSClusterConfig.Annotations = expectedOSSClusterConfig.Annotations

		_, err = clusterConfigClientSet.Update(ctx, runningOSSClusterConfig, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = clusterConfigClientSet.Create(ctx, expectedOSSClusterConfig, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.WithFields(logrus.Fields{
		"cluster config": entClusterConfig.GetName(),
	}).Debug("OSS BGP Cluster Config updated")

	return nil
}

func (m *BGPResourceMapper) mapPeerConfigs(ctx context.Context) error {
	entPeerConfigs, err := m.peerConfig.List()
	if err != nil {
		return err
	}

	for _, entPeerConfig := range entPeerConfigs {
		err = errors.Join(err, m.mapPeerConfig(ctx, entPeerConfig))
	}
	return err
}

func (m *BGPResourceMapper) mapPeerConfig(ctx context.Context, entPeerConfig *v1alpha1.IsovalentBGPPeerConfig) error {
	expectedOSSPeerConfig := createOSSPeerConfig(entPeerConfig)
	runningOSSPeerConfig, exists, err := m.ossPeerConfigStore.GetByKey(resource.Key{
		Name:      entPeerConfig.GetName(),
		Namespace: entPeerConfig.GetNamespace(),
	})
	if err != nil {
		return err
	}

	peerConfigClientSet := m.clientSet.CiliumV2alpha1().CiliumBGPPeerConfigs()

	switch {
	case exists && expectedOSSPeerConfig.Spec.DeepEqual(&runningOSSPeerConfig.Spec) &&
		maps.Equal(expectedOSSPeerConfig.Labels, runningOSSPeerConfig.Labels) &&
		maps.Equal(expectedOSSPeerConfig.Annotations, runningOSSPeerConfig.Annotations):
		return nil

	case exists:
		// update
		runningOSSPeerConfig.Spec = expectedOSSPeerConfig.Spec
		runningOSSPeerConfig.Labels = expectedOSSPeerConfig.Labels
		runningOSSPeerConfig.Annotations = expectedOSSPeerConfig.Annotations

		_, err = peerConfigClientSet.Update(ctx, runningOSSPeerConfig, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = peerConfigClientSet.Create(ctx, expectedOSSPeerConfig, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.WithFields(logrus.Fields{
		"peer config": entPeerConfig.GetName(),
	}).Debug("OSS BGP Peer Config updated")

	return nil
}

func (m *BGPResourceMapper) mapAdvertisements(ctx context.Context) error {
	entAdvertisements, err := m.advertisements.List()
	if err != nil {
		return err
	}

	for _, entAdvertisement := range entAdvertisements {
		err = errors.Join(err, m.mapAdvertisement(ctx, entAdvertisement))
	}
	return err
}

func (m *BGPResourceMapper) mapAdvertisement(ctx context.Context, entAdvertisement *v1alpha1.IsovalentBGPAdvertisement) error {
	expectedOSSAdvertisement := createOSSAdvertisement(entAdvertisement)
	runningOSSAdvertisement, exists, err := m.ossAdvertStore.GetByKey(resource.Key{
		Name:      entAdvertisement.GetName(),
		Namespace: entAdvertisement.GetNamespace(),
	})
	if err != nil {
		return err
	}

	advertisementClientSet := m.clientSet.CiliumV2alpha1().CiliumBGPAdvertisements()

	switch {
	case exists && expectedOSSAdvertisement.Spec.DeepEqual(&runningOSSAdvertisement.Spec) &&
		maps.Equal(expectedOSSAdvertisement.Labels, runningOSSAdvertisement.Labels) &&
		maps.Equal(expectedOSSAdvertisement.Annotations, runningOSSAdvertisement.Annotations):
		return nil

	case exists:
		// update
		runningOSSAdvertisement.Spec = expectedOSSAdvertisement.Spec
		runningOSSAdvertisement.Labels = expectedOSSAdvertisement.Labels
		runningOSSAdvertisement.Annotations = expectedOSSAdvertisement.Annotations

		_, err = advertisementClientSet.Update(ctx, runningOSSAdvertisement, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = advertisementClientSet.Create(ctx, expectedOSSAdvertisement, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.WithFields(logrus.Fields{
		"advertisement": entAdvertisement.GetName(),
	}).Debug("OSS BGP Advertisement updated")

	return nil
}

func (m *BGPResourceMapper) mapNodeConfigOverrides(ctx context.Context) error {
	entNodeConfigOverrides, err := m.nodeConfigOverride.List()
	if err != nil {
		return err
	}

	for _, entNodeConfigOverride := range entNodeConfigOverrides {
		err = errors.Join(err, m.mapNodeConfigOverride(ctx, entNodeConfigOverride))
	}
	return err
}

func (m *BGPResourceMapper) mapNodeConfigOverride(ctx context.Context, entNodeConfigOverride *v1alpha1.IsovalentBGPNodeConfigOverride) error {
	expectedOSSNodeConfigOverride := createOSSNodeConfigOverride(entNodeConfigOverride)
	runningOSSNodeConfigOverride, exists, err := m.ossNodeConfigOverrideStore.GetByKey(resource.Key{
		Name:      entNodeConfigOverride.GetName(),
		Namespace: entNodeConfigOverride.GetNamespace(),
	})
	if err != nil {
		return err
	}

	nodeConfigOverrideClientSet := m.clientSet.CiliumV2alpha1().CiliumBGPNodeConfigOverrides()

	switch {
	case exists && expectedOSSNodeConfigOverride.Spec.DeepEqual(&runningOSSNodeConfigOverride.Spec) &&
		maps.Equal(expectedOSSNodeConfigOverride.Labels, runningOSSNodeConfigOverride.Labels) &&
		maps.Equal(expectedOSSNodeConfigOverride.Annotations, runningOSSNodeConfigOverride.Annotations):
		return nil

	case exists:
		// update
		runningOSSNodeConfigOverride.Spec = expectedOSSNodeConfigOverride.Spec
		runningOSSNodeConfigOverride.Labels = expectedOSSNodeConfigOverride.Labels
		runningOSSNodeConfigOverride.Annotations = expectedOSSNodeConfigOverride.Annotations

		_, err = nodeConfigOverrideClientSet.Update(ctx, runningOSSNodeConfigOverride, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = nodeConfigOverrideClientSet.Create(ctx, expectedOSSNodeConfigOverride, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.WithFields(logrus.Fields{
		"node config override": entNodeConfigOverride.GetName(),
	}).Debug("OSS BGP Node Config Override updated")

	return nil
}

func createOSSClusterConfig(entClusterConfig *v1alpha1.IsovalentBGPClusterConfig) *v2alpha1.CiliumBGPClusterConfig {
	newOSSClusterConfig := &v2alpha1.CiliumBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entClusterConfig.GetName(),
			Namespace:   entClusterConfig.GetNamespace(),
			Labels:      entClusterConfig.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entClusterConfig.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentBGPClusterConfigKindDefinition,
					Name:       entClusterConfig.GetName(),
					UID:        entClusterConfig.GetUID(),
				},
			},
		},
		Spec: v2alpha1.CiliumBGPClusterConfigSpec{
			NodeSelector: entClusterConfig.Spec.NodeSelector,
		},
	}

	for _, bgpInstance := range entClusterConfig.Spec.BGPInstances {
		ossBGPInstance := v2alpha1.CiliumBGPInstance{
			Name:     bgpInstance.Name,
			LocalASN: bgpInstance.LocalASN,
		}

		for _, peer := range bgpInstance.Peers {
			ossBGPInstance.Peers = append(ossBGPInstance.Peers, v2alpha1.CiliumBGPPeer{
				Name:        peer.Name,
				PeerAddress: peer.PeerAddress,
				PeerASN:     peer.PeerASN,
				PeerConfigRef: &v2alpha1.PeerConfigReference{
					Name: peer.PeerConfigRef.Name,
				},
			})
		}

		newOSSClusterConfig.Spec.BGPInstances = append(newOSSClusterConfig.Spec.BGPInstances, ossBGPInstance)
	}

	return newOSSClusterConfig
}

func createOSSPeerConfig(entPeerConfig *v1alpha1.IsovalentBGPPeerConfig) *v2alpha1.CiliumBGPPeerConfig {
	newOSSPeerConfig := &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entPeerConfig.GetName(),
			Namespace:   entPeerConfig.GetNamespace(),
			Labels:      entPeerConfig.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entPeerConfig.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentBGPPeerConfigKindDefinition,
					Name:       entPeerConfig.GetName(),
					UID:        entPeerConfig.GetUID(),
				},
			},
		},
		Spec: entPeerConfig.Spec.CiliumBGPPeerConfigSpec,
	}

	return newOSSPeerConfig
}

func createOSSAdvertisement(entAdvertisement *v1alpha1.IsovalentBGPAdvertisement) *v2alpha1.CiliumBGPAdvertisement {
	newOSSAdvertisement := &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entAdvertisement.GetName(),
			Namespace:   entAdvertisement.GetNamespace(),
			Labels:      entAdvertisement.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entAdvertisement.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentBGPAdvertisementKindDefinition,
					Name:       entAdvertisement.GetName(),
					UID:        entAdvertisement.GetUID(),
				},
			},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{},
		},
	}

	for _, advert := range entAdvertisement.Spec.Advertisements {
		advertType := ossAdvertTypeFromEnt(advert.AdvertisementType)
		if advertType == "unknown" {
			// skip enterprise advertisement types that are not supported in OSS
			continue
		}

		ossAdvert := v2alpha1.BGPAdvertisement{
			AdvertisementType: advertType,
			Service:           ossServiceOptionFromEnt(advert.Service),
			Selector:          advert.Selector,
			Attributes:        advert.Attributes,
		}
		newOSSAdvertisement.Spec.Advertisements = append(newOSSAdvertisement.Spec.Advertisements, ossAdvert)
	}

	return newOSSAdvertisement
}

func ossServiceOptionFromEnt(advert *v1alpha1.BGPServiceOptions) *v2alpha1.BGPServiceOptions {
	if advert == nil {
		return nil
	}

	return &v2alpha1.BGPServiceOptions{
		Addresses: advert.Addresses,
	}
}

func ossAdvertTypeFromEnt(advert v1alpha1.IsovalentBGPAdvertType) v2alpha1.BGPAdvertisementType {
	switch advert {
	case v1alpha1.BGPPodCIDRAdvert:
		return v2alpha1.BGPPodCIDRAdvert
	case v1alpha1.BGPServiceAdvert:
		return v2alpha1.BGPServiceAdvert
	case v1alpha1.BGPCiliumPodIPPoolAdvert:
		return v2alpha1.BGPCiliumPodIPPoolAdvert
	}
	return "unknown"
}

func createOSSNodeConfigOverride(entNodeConfigOverride *v1alpha1.IsovalentBGPNodeConfigOverride) *v2alpha1.CiliumBGPNodeConfigOverride {
	newOSSNodeConfigOverride := &v2alpha1.CiliumBGPNodeConfigOverride{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entNodeConfigOverride.GetName(),
			Namespace:   entNodeConfigOverride.GetNamespace(),
			Labels:      entNodeConfigOverride.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entNodeConfigOverride.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentBGPNodeConfigOverrideKindDefinition,
					Name:       entNodeConfigOverride.GetName(),
					UID:        entNodeConfigOverride.GetUID(),
				},
			},
		},
	}

	for _, bgpInstance := range entNodeConfigOverride.Spec.BGPInstances {
		ossBGPInstance := v2alpha1.CiliumBGPNodeConfigInstanceOverride{
			Name:      bgpInstance.Name,
			RouterID:  bgpInstance.RouterID,
			LocalPort: bgpInstance.LocalPort,
		}

		for _, peer := range bgpInstance.Peers {
			ossBGPInstance.Peers = append(ossBGPInstance.Peers, v2alpha1.CiliumBGPNodeConfigPeerOverride{
				Name:         peer.Name,
				LocalAddress: peer.LocalAddress,
				LocalPort:    peer.LocalPort,
			})
		}

		newOSSNodeConfigOverride.Spec.BGPInstances = append(newOSSNodeConfigOverride.Spec.BGPInstances, ossBGPInstance)
	}

	return newOSSNodeConfigOverride
}

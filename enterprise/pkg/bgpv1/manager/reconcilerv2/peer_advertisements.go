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
	"errors"
	"sort"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type (
	// PeerAdvertisements is a map of peer name to its family advertisements
	// This is the top level map that is returned to the consumer with requested advertisements.
	PeerAdvertisements       map[string]PeerFamilyAdvertisements
	PeerFamilyAdvertisements map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement // key is the address family type
)

type PeerAdvertisementIn struct {
	cell.In

	Group              job.Group
	Logger             logrus.FieldLogger
	PeerConfigResource resource.Resource[*v1alpha1.IsovalentBGPPeerConfig]
	AdvertResource     resource.Resource[*v1alpha1.IsovalentBGPAdvertisement]
}

type IsovalentPeerAdvertisement struct {
	initialized atomic.Bool
	logger      logrus.FieldLogger
	peerConfig  resource.Store[*v1alpha1.IsovalentBGPPeerConfig]
	adverts     resource.Store[*v1alpha1.IsovalentBGPAdvertisement]
}

func newIsovalentPeerAdvertisement(p PeerAdvertisementIn) *IsovalentPeerAdvertisement {
	pa := &IsovalentPeerAdvertisement{
		logger: p.Logger,
	}
	p.Group.Add(job.OneShot("init-peer-advertisement", func(ctx context.Context, health cell.Health) error {
		pcs, err := p.PeerConfigResource.Store(ctx)
		if err != nil {
			return err
		}

		as, err := p.AdvertResource.Store(ctx)
		if err != nil {
			return err
		}

		pa.peerConfig = pcs
		pa.adverts = as

		pa.initialized.Store(true)

		return nil
	}))
	return pa
}

// GetConfiguredAdvertisements can be called to get all configured advertisements of given BGPAdvertisementType for each peer.
// Advertisements are selected based on below criteria:
// Each peer is selected from the BGP node instance configuration. For each peer, the peer configuration is fetched
// from local store.
// Peer configuration contains the list of families and the advertisement selector.
// We iterate over all advertisements ( available from local store ), select only those that match the advertisement
// selector of the family.
// Information of peer -> family -> advertisements is returned to the consumer.
// Linear scan [ Peers ] - O(n) ( number of peers )
// Linear scan [ Families ] - O(m) ( max 2 )
// Linear scan [ Advertisements ] - O(k) ( number of advertisements - 3-4 types, which is again filtered)
func (p *IsovalentPeerAdvertisement) GetConfiguredAdvertisements(conf *v1alpha1.IsovalentBGPNodeInstance, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) (PeerAdvertisements, error) {
	if !p.initialized.Load() {
		return make(PeerAdvertisements), nil
	}

	result := make(PeerAdvertisements)
	l := p.logger.WithField(types.InstanceLogField, conf.Name)
	for _, peer := range conf.Peers {
		lp := l.WithField(types.PeerLogField, peer.Name)

		peerConfig, exist, err := p.peerConfig.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
		if err != nil {
			if errors.Is(err, store.ErrStoreUninitialized) {
				lp.Errorf("BUG: Peer config store is not initialized")
			}
			return nil, err
		}

		if !exist {
			lp.Debug("Peer config not found, skipping advertisement check")
			continue
		}

		peerAdverts, err := p.getPeerAdvertisements(peerConfig, selectAdvertTypes...)
		if err != nil {
			return nil, err
		}
		result[peer.Name] = peerAdverts
	}
	return result, nil
}

func (p *IsovalentPeerAdvertisement) getPeerAdvertisements(peerConfig *v1alpha1.IsovalentBGPPeerConfig, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) (PeerFamilyAdvertisements, error) {
	result := make(map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement)

	for _, family := range peerConfig.Spec.Families {
		advert, err := p.getFamilyAdvertisements(family, selectAdvertTypes...)
		if err != nil {
			return result, err
		}
		result[family.CiliumBGPFamily] = advert
	}
	return result, nil
}

func (p *IsovalentPeerAdvertisement) getFamilyAdvertisements(family v2alpha1.CiliumBGPFamilyWithAdverts, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) ([]v1alpha1.BGPAdvertisement, error) {
	// get all advertisement CRD objects.
	advertResources := p.adverts.List()

	// select only label selected advertisements for the family
	selectedAdvertResources, err := p.familySelectedAdvertisements(family, advertResources)
	if err != nil {
		return nil, err
	}

	// create selectTypeSet for easier lookup
	selectTypesSet := sets.New[string]()
	for _, selectType := range selectAdvertTypes {
		selectTypesSet.Insert(string(selectType))
	}

	var selectedAdvertisements []v1alpha1.BGPAdvertisement
	// select advertisements requested by the consumer
	for _, advertResource := range selectedAdvertResources {
		for _, advert := range advertResource.Spec.Advertisements {
			// check if the advertisement type is in the selectType set
			if selectTypesSet.Has(string(advert.AdvertisementType)) {
				selectedAdvertisements = append(selectedAdvertisements, advert)
			}
		}
	}

	return selectedAdvertisements, nil
}

func (p *IsovalentPeerAdvertisement) familySelectedAdvertisements(family v2alpha1.CiliumBGPFamilyWithAdverts, adverts []*v1alpha1.IsovalentBGPAdvertisement) ([]*v1alpha1.IsovalentBGPAdvertisement, error) {
	var result []*v1alpha1.IsovalentBGPAdvertisement
	advertSelector, err := slim_metav1.LabelSelectorAsSelector(family.Advertisements)
	if err != nil {
		return nil, err
	}

	for _, advert := range adverts {
		if advertSelector.Matches(labels.Set(advert.Labels)) {
			result = append(result, advert)
		}
	}
	return result, nil
}

func PeerAdvertisementsEqual(first, second PeerAdvertisements) bool {
	if len(first) != len(second) {
		return false
	}

	for peer, peerAdverts := range first {
		if !FamilyAdvertisementsEqual(peerAdverts, second[peer]) {
			return false
		}
	}
	return true
}

func FamilyAdvertisementsEqual(first, second PeerFamilyAdvertisements) bool {
	if len(first) != len(second) {
		return false
	}

	for family, familyAdverts := range first {
		otherFamilyAdverts, exist := second[family]
		if !exist || len(familyAdverts) != len(otherFamilyAdverts) {
			return false
		}

		sort.Slice(familyAdverts, func(i, j int) bool {
			return familyAdverts[i].AdvertisementType < familyAdverts[j].AdvertisementType
		})

		sort.Slice(otherFamilyAdverts, func(i, j int) bool {
			return otherFamilyAdverts[i].AdvertisementType < otherFamilyAdverts[j].AdvertisementType
		})

		for i, advert := range familyAdverts {
			if !advert.DeepEqual(&otherFamilyAdverts[i]) {
				return false
			}
		}
	}
	return true
}

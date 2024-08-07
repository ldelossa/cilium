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

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
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
	PeerAdvertisements map[string]FamilyAdvertisements

	// VRFAdvertisements is a map of VRF name to its family advertisements
	VRFAdvertisements map[string]FamilyAdvertisements

	// FamilyAdvertisements is a map of address family to its advertisements
	FamilyAdvertisements map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement
)

type AdvertisementIn struct {
	cell.In

	Group              job.Group
	Logger             logrus.FieldLogger
	Config             config.Config
	PeerConfigResource resource.Resource[*v1alpha1.IsovalentBGPPeerConfig]
	AdvertResource     resource.Resource[*v1alpha1.IsovalentBGPAdvertisement]
	VRFConfigStore     store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]
}

type IsovalentAdvertisement struct {
	initialized atomic.Bool
	logger      logrus.FieldLogger
	peerConfig  resource.Store[*v1alpha1.IsovalentBGPPeerConfig]
	adverts     resource.Store[*v1alpha1.IsovalentBGPAdvertisement]

	// we want to trigger BGP reconciliation if there is change detected in IsovalentBGPVRFConfig
	// so we initialize BGPCPResourceStore for IsovalentBGPVRFConfig
	vrfs store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]
}

func newIsovalentAdvertisement(p AdvertisementIn) *IsovalentAdvertisement {
	pa := &IsovalentAdvertisement{
		logger: p.Logger.WithField(types.ReconcilerLogField, "advertisements"),
		vrfs:   p.VRFConfigStore,
	}
	// Check if enterprise BGP control plane is enabled
	if !p.Config.Enabled {
		return pa
	}
	p.Group.Add(job.OneShot("init-advertisements", func(ctx context.Context, health cell.Health) error {
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

// GetConfiguredPeerAdvertisements can be called to get all configured advertisements of given BGPAdvertisementType for each peer.
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
func (p *IsovalentAdvertisement) GetConfiguredPeerAdvertisements(conf *v1alpha1.IsovalentBGPNodeInstance, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) (PeerAdvertisements, error) {
	if !p.initialized.Load() {
		return make(PeerAdvertisements), nil
	}

	result := make(PeerAdvertisements)
	l := p.logger.WithField(types.InstanceLogField, conf.Name)
	for _, peer := range conf.Peers {
		lp := l.WithField(types.PeerLogField, peer.Name)

		if peer.PeerConfigRef == nil {
			lp.Debug("Peer config ref not set, skipping advertisement check")
			continue
		}

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

func (p *IsovalentAdvertisement) getPeerAdvertisements(peerConfig *v1alpha1.IsovalentBGPPeerConfig, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) (FamilyAdvertisements, error) {
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

func (p *IsovalentAdvertisement) getFamilyAdvertisements(family v2alpha1.CiliumBGPFamilyWithAdverts, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) ([]v1alpha1.BGPAdvertisement, error) {
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

func (p *IsovalentAdvertisement) familySelectedAdvertisements(family v2alpha1.CiliumBGPFamilyWithAdverts, adverts []*v1alpha1.IsovalentBGPAdvertisement) ([]*v1alpha1.IsovalentBGPAdvertisement, error) {
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

func (p *IsovalentAdvertisement) GetConfiguredVRFAdvertisements(conf *v1alpha1.IsovalentBGPNodeInstance, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) (VRFAdvertisements, error) {
	if !p.initialized.Load() {
		p.logger.Debug("IsovalentAdvertisement reconciler helper is not initialized")
		return make(VRFAdvertisements), nil
	}

	result := make(VRFAdvertisements)
	l := p.logger.WithField(types.InstanceLogField, conf.Name)

	for _, vrf := range conf.VRFs {
		lv := l.WithField(entTypes.VRFLogField, vrf.VRFRef)

		if vrf.ConfigRef == nil {
			lv.Debug("VRF config ref not set, skipping advertisement check")
			continue
		}

		vrfConfig, exist, err := p.vrfs.GetByKey(resource.Key{Name: *vrf.ConfigRef})
		if err != nil {
			if errors.Is(err, store.ErrStoreUninitialized) {
				lv.Debug("VRF config store is not initialized")
			}
			return nil, err
		}

		if !exist {
			lv.Debug("VRF config not found, skipping advertisement check")
			continue
		}

		vrfAdverts, err := p.getVRFAdvertisements(vrfConfig, selectAdvertTypes...)
		if err != nil {
			return nil, err
		}
		result[vrf.VRFRef] = vrfAdverts
	}
	return result, nil
}

func (p *IsovalentAdvertisement) getVRFAdvertisements(vrfConfig *v1alpha1.IsovalentBGPVRFConfig, selectAdvertTypes ...v1alpha1.IsovalentBGPAdvertType) (FamilyAdvertisements, error) {
	result := make(map[v2alpha1.CiliumBGPFamily][]v1alpha1.BGPAdvertisement)

	for _, family := range vrfConfig.Spec.Families {
		advert, err := p.getFamilyAdvertisements(family, selectAdvertTypes...)
		if err != nil {
			return result, err
		}
		result[family.CiliumBGPFamily] = advert
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

func VRFAdvertisementsEqual(first, second VRFAdvertisements) bool {
	if len(first) != len(second) {
		return false
	}

	for vrf, vrfAdverts := range first {
		if !FamilyAdvertisementsEqual(vrfAdverts, second[vrf]) {
			return false
		}
	}
	return true
}

func FamilyAdvertisementsEqual(first, second FamilyAdvertisements) bool {
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

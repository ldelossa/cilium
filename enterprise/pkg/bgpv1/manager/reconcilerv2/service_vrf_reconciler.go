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
	"fmt"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
)

type ServiceVRFReconcilerIn struct {
	cell.In

	Logger       logrus.FieldLogger
	Config       config.Config
	DaemonConfig *option.DaemonConfig
	Adverts      *IsovalentAdvertisement
	SvcDiffStore store.DiffStore[*slim_corev1.Service]
	EPDiffStore  store.DiffStore[*k8s.Endpoints]
	Upgrader     paramUpgrader
	SRv6Paths    *srv6Paths
	SRv6Manager  *srv6.Manager
}

type ServiceVRFReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type ServiceVRFReconciler struct {
	logger       logrus.FieldLogger
	adverts      *IsovalentAdvertisement
	svcDiffStore store.DiffStore[*slim_corev1.Service]
	epDiffStore  store.DiffStore[*k8s.Endpoints]
	upgrader     paramUpgrader
	srv6Paths    *srv6Paths
	srv6Manager  SRv6Manager
}

func NewServiceVRFReconciler(in ServiceVRFReconcilerIn) ServiceVRFReconcilerOut {
	if !in.Config.Enabled || !in.DaemonConfig.EnableSRv6 {
		return ServiceVRFReconcilerOut{}
	}

	return ServiceVRFReconcilerOut{
		Reconciler: &ServiceVRFReconciler{
			logger:       in.Logger.WithField(types.ReconcilerLogField, "ServiceVRF"),
			adverts:      in.Adverts,
			svcDiffStore: in.SvcDiffStore,
			epDiffStore:  in.EPDiffStore,
			upgrader:     in.Upgrader,
			srv6Paths:    in.SRv6Paths,
			srv6Manager:  in.SRv6Manager,
		},
	}
}

// VRFPaths is a map type that contains service paths for a VRF, key being the VRF name.
type VRFPaths map[string]reconcilerv2.ResourceAFPathsMap

// VRFSIDInfo is a map type that contains SRv6 SID information for a VRF, key being the VRF name.
type VRFSIDInfo map[string]*sidmanager.SIDInfo

// ServiceVRFReconcilerMetadata contains metadata for service VRF reconciler, metadata is stored per
// BGP instance.
type ServiceVRFReconcilerMetadata struct {
	// path programmed in underlying bgp instance
	vrfPaths VRFPaths

	// vrfAdverts contains BGP advertisements associated with VRFs
	vrfAdverts VRFAdvertisements

	// vrfConfigs contains BGP RD/RT configuration for VRFs
	vrfConfigs []v1alpha1.IsovalentBGPNodeVRF

	// vrfSIDs contains SRv6 SID information for VRFs, like SID structure and behavior
	vrfSIDs VRFSIDInfo
}

func (r *ServiceVRFReconciler) getMetadata(i *EnterpriseBGPInstance) ServiceVRFReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = ServiceVRFReconcilerMetadata{
			vrfPaths:   make(VRFPaths),
			vrfAdverts: make(VRFAdvertisements),
			vrfSIDs:    make(VRFSIDInfo),
		}
	}
	return i.Metadata[r.Name()].(ServiceVRFReconcilerMetadata)
}

func (r *ServiceVRFReconciler) setMetadata(i *EnterpriseBGPInstance, metadata ServiceVRFReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}

func (r *ServiceVRFReconciler) Name() string {
	return "ServiceVRF"
}

func (r *ServiceVRFReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: service VRF reconciler initialization with nil BGPInstance")
	}
	r.svcDiffStore.InitDiff(r.diffID(i.ASN))
	r.epDiffStore.InitDiff(r.diffID(i.ASN))
	return nil
}

func (r *ServiceVRFReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		r.svcDiffStore.CleanupDiff(r.diffID(i.ASN))
		r.epDiffStore.CleanupDiff(r.diffID(i.ASN))
	}
}

func (r *ServiceVRFReconciler) diffID(asn uint32) string {
	return fmt.Sprintf("%s-%d", r.Name(), asn)
}

func (r *ServiceVRFReconciler) Priority() int {
	return 41 // Right after OSS service reconciler
}

func (r *ServiceVRFReconciler) Reconcile(ctx context.Context, p reconcilerv2.ReconcileParams) error {
	iParams, err := r.upgrader.upgrade(p)
	if err != nil {
		if errors.Is(err, NotInitializedErr) {
			r.logger.Debug("Initialization is not done, skipping service VRF reconciliation")
			return nil
		}
		return err
	}

	desiredVRFAdverts, err := r.adverts.GetConfiguredVRFAdvertisements(iParams.DesiredConfig, v1alpha1.BGPServiceAdvert)
	if err != nil {
		return fmt.Errorf("failed to get configured VRF advertisements: %w", err)
	}

	desiredVRFSIDInfo, err := r.getConfiguredSIDInfo(iParams.DesiredConfig)
	if err != nil {
		return fmt.Errorf("failed to get SID info: %w", err)
	}

	ls, err := r.populateLocalServices(p.CiliumNode.Name)
	if err != nil {
		return fmt.Errorf("failed to populate local services: %w", err)
	}

	err = r.reconcileServices(ctx, iParams, ls, desiredVRFAdverts, desiredVRFSIDInfo)
	if err != nil {
		return fmt.Errorf("failed to reconcile services: %w", err)
	}

	// update metadata with the latest configuration
	r.setMetadata(iParams.BGPInstance, ServiceVRFReconcilerMetadata{
		vrfPaths:   r.getMetadata(iParams.BGPInstance).vrfPaths,
		vrfAdverts: desiredVRFAdverts,
		vrfConfigs: iParams.DesiredConfig.VRFs,
		vrfSIDs:    desiredVRFSIDInfo,
	})
	return nil
}

func (r *ServiceVRFReconciler) reconcileServices(ctx context.Context, p EnterpriseReconcileParams, ls sets.Set[resource.Key], desiredVRFAdverts VRFAdvertisements, desiredVRFSIDInfo VRFSIDInfo) error {
	desiredVRFPaths := make(VRFPaths)

	// check if vrf is removed, we clean up the service paths.
	metadata := r.getMetadata(p.BGPInstance)
	for runningVRF := range metadata.vrfPaths {
		found := false
		for _, desiredVRF := range p.DesiredConfig.VRFs {
			if runningVRF == desiredVRF.VRFRef {
				found = true
				break
			}
		}

		if !found {
			// mark VRF for cleanup
			desiredVRFPaths[runningVRF] = nil
		}
	}

	if r.configModified(p, desiredVRFAdverts, desiredVRFSIDInfo) {
		r.logger.Debug("performing all services reconciliation")

		r.svcDiffStore.InitDiff(r.diffID(p.BGPInstance.ASN))
		r.epDiffStore.InitDiff(r.diffID(p.BGPInstance.ASN))

		for _, vrf := range p.DesiredConfig.VRFs {
			// BGP configuration for service advertisement changed, we should reconcile all services.
			desiredSvcPaths, err := r.getAllPaths(p, ls, vrf, desiredVRFAdverts)
			if err != nil {
				return err
			}
			desiredVRFPaths[vrf.VRFRef] = desiredSvcPaths
		}
	} else {
		r.logger.Debug("performing modified services reconciliation")

		// get services to reconcile and to withdraw.
		// Note : we should only call svc diff only once in a reconcile loop.
		toReconcile, toWithdraw, err := r.diffReconciliationServiceList(p.BGPInstance)
		if err != nil {
			return err
		}

		for _, vrf := range p.DesiredConfig.VRFs {
			// BGP configuration is unchanged, only reconcile modified services.
			updatedSvcPaths, err := r.getDiffPaths(toReconcile, toWithdraw, ls, vrf, desiredVRFAdverts)
			if err != nil {
				return err
			}

			// We need to only update modified services in the VRF. If VRF does not exist
			// in metadata, we just create a new entry with updatedSvcPaths. Otherwise,
			// we need to only touch services which are modified.

			// check if vrf is present
			currentSvcPaths, exists := metadata.vrfPaths[vrf.VRFRef]
			if !exists {
				desiredVRFPaths[vrf.VRFRef] = updatedSvcPaths
				continue
			}

			// update modified services
			desiredSvcPaths := make(reconcilerv2.ResourceAFPathsMap)
			maps.Copy(desiredSvcPaths, currentSvcPaths)

			// override only modified services
			for svcKey, svcAFPaths := range updatedSvcPaths {
				desiredSvcPaths[svcKey] = svcAFPaths
			}
			desiredVRFPaths[vrf.VRFRef] = desiredSvcPaths
		}
	}

	return r.reconcileVRFs(ctx, p, desiredVRFPaths)
}

func (r *ServiceVRFReconciler) reconcileVRFs(ctx context.Context, p EnterpriseReconcileParams, desiredVRFPaths VRFPaths) error {
	var err error
	for vrf, desiredPaths := range desiredVRFPaths {
		// desiredPaths can be nil, in which case we need to clean up the paths for this VRF. ReconcilePaths should handle
		// nil desiredPaths.
		updatedSvcPaths, rErr := r.reconcilePaths(ctx, p, vrf, r.getMetadata(p.BGPInstance).vrfPaths[vrf], desiredPaths)
		if rErr == nil && len(updatedSvcPaths) == 0 {
			delete(r.getMetadata(p.BGPInstance).vrfPaths, vrf)
		} else {
			r.getMetadata(p.BGPInstance).vrfPaths[vrf] = updatedSvcPaths
		}
		err = errors.Join(err, rErr)
	}
	return err
}

func (r *ServiceVRFReconciler) reconcilePaths(ctx context.Context, p EnterpriseReconcileParams, vrfName string, currentSvcPaths, desiredSvcPaths reconcilerv2.ResourceAFPathsMap) (reconcilerv2.ResourceAFPathsMap, error) {
	var err error
	updatedSvcPaths := make(reconcilerv2.ResourceAFPathsMap)

	if len(desiredSvcPaths) == 0 {
		// cleanup current services
		for svcKey, currentAFPaths := range currentSvcPaths {
			// reconcile service paths
			updatedAFPaths, rErr := reconcilerv2.ReconcileAFPaths(&reconcilerv2.ReconcileAFPathsParams{
				Logger: r.logger.WithFields(logrus.Fields{
					types.InstanceLogField: p.DesiredConfig.Name,
					entTypes.VRFLogField:   vrfName,
				}),
				Ctx:          ctx,
				Router:       p.BGPInstance.Router,
				DesiredPaths: nil,
				CurrentPaths: currentAFPaths,
			})
			if rErr != nil {
				// Since there is some error condition, keep svc in updatedSvcPaths.
				// Under no error condition svc will not be present in updatedSvcPaths map and caller
				// can cleanup this service.
				updatedSvcPaths[svcKey] = updatedAFPaths
				err = errors.Join(err, rErr)
			}
		}
		return updatedSvcPaths, err
	}

	for svcKey, desiredAFPaths := range desiredSvcPaths {
		currentAFPaths, exists := currentSvcPaths[svcKey]
		if !exists && len(desiredAFPaths) == 0 {
			// nothing to do
			continue
		}

		// reconcile service paths
		updatedAFPaths, rErr := reconcilerv2.ReconcileAFPaths(&reconcilerv2.ReconcileAFPathsParams{
			Logger: r.logger.WithFields(logrus.Fields{
				types.InstanceLogField: p.DesiredConfig.Name,
				entTypes.VRFLogField:   vrfName,
			}),
			Ctx:          ctx,
			Router:       p.BGPInstance.Router,
			DesiredPaths: desiredAFPaths,
			CurrentPaths: currentAFPaths,
		})
		if rErr == nil && len(updatedAFPaths) == 0 {
			// do not add this service to updatedSvcPaths, since we removed all AFPaths for this service.
			// caller can cleanup this service.
			continue
		}
		updatedSvcPaths[svcKey] = updatedAFPaths
		err = errors.Join(err, rErr)
	}
	return updatedSvcPaths, err
}

func (r *ServiceVRFReconciler) getAllPaths(p EnterpriseReconcileParams, ls sets.Set[resource.Key], bgpVRF v1alpha1.IsovalentBGPNodeVRF, desiredVRFAdverts VRFAdvertisements) (reconcilerv2.ResourceAFPathsMap, error) {
	desiredServiceAFPaths := make(reconcilerv2.ResourceAFPathsMap)

	// check for services which are no longer present
	if serviceAFPaths, vrfExists := r.getMetadata(p.BGPInstance).vrfPaths[bgpVRF.VRFRef]; vrfExists {
		for svcKey := range serviceAFPaths {
			_, exists, err := r.svcDiffStore.GetByKey(svcKey)
			if err != nil {
				return nil, fmt.Errorf("svcDiffStore.GetByKey(): %w", err)
			}

			// if the service no longer exists, withdraw it
			if !exists {
				desiredServiceAFPaths[svcKey] = nil
			}
		}
	}

	// check all services for advertisement
	svcList, err := r.svcDiffStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list services from svcDiffstore: %w", err)
	}

	for _, svc := range svcList {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		afPaths, err := r.getServiceAFPaths(svc, ls, bgpVRF, desiredVRFAdverts)
		if err != nil {
			return nil, err
		}

		desiredServiceAFPaths[svcKey] = afPaths
	}

	return desiredServiceAFPaths, nil
}

func (r *ServiceVRFReconciler) diffReconciliationServiceList(i *EnterpriseBGPInstance) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	upserted, deleted, err := r.svcDiffStore.Diff(r.diffID(i.ASN))
	if err != nil {
		return nil, nil, fmt.Errorf("svc store diff: %w", err)
	}

	// For externalTrafficPolicy=local, we need to take care of
	// the endpoint changes in addition to the service changes.
	// Take a diff of the EPs and get affected services.
	// We don't handle service deletion here since we only see
	// the key, we cannot resolve associated service, so we have
	// nothing to do.
	epsUpserted, _, err := r.epDiffStore.Diff(r.diffID(i.ASN))
	if err != nil {
		return nil, nil, fmt.Errorf("EPs store diff: %w", err)
	}

	for _, eps := range epsUpserted {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from EPs. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
			// We only care about LoadBalancer services.
			continue
		}

		upserted = append(upserted, svc)
	}

	// We may have duplicated services that changes happened for both of
	// service and associated EPs.
	deduped := ciliumslices.UniqueFunc(
		upserted,
		func(i int) resource.Key {
			return resource.Key{
				Name:      upserted[i].GetName(),
				Namespace: upserted[i].GetNamespace(),
			}
		},
	)

	return deduped, deleted, nil
}

func (r *ServiceVRFReconciler) getDiffPaths(
	toReconcile []*slim_corev1.Service,
	toWithdraw []resource.Key,
	ls sets.Set[resource.Key],
	bgpVRF v1alpha1.IsovalentBGPNodeVRF,
	desiredVRFAdverts VRFAdvertisements,
) (reconcilerv2.ResourceAFPathsMap, error) {

	desiredServiceAFPaths := make(reconcilerv2.ResourceAFPathsMap)
	for _, svc := range toReconcile {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		afPaths, err := r.getServiceAFPaths(svc, ls, bgpVRF, desiredVRFAdverts)
		if err != nil {
			return nil, err
		}

		desiredServiceAFPaths[svcKey] = afPaths
	}

	for _, svcKey := range toWithdraw {
		// for withdrawn services, we need to set paths to nil.
		desiredServiceAFPaths[svcKey] = nil
	}

	return desiredServiceAFPaths, nil
}

func (r *ServiceVRFReconciler) getServiceAFPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key], bgpVRF v1alpha1.IsovalentBGPNodeVRF, desiredVRFAdverts VRFAdvertisements) (reconcilerv2.AFPathsMap, error) {
	desiredFamilyPaths := make(reconcilerv2.AFPathsMap)

	vrfFamilyAdvertisements, exists := desiredVRFAdverts[bgpVRF.VRFRef]
	if !exists {
		// no advertisement found for this VRF, nothing to do.
		return nil, nil
	}

	for family, familyAdverts := range vrfFamilyAdvertisements {
		agentFamily := types.ToAgentFamily(family)

		for _, advert := range familyAdverts {
			// get prefixes for the service
			desiredPrefixes, err := r.getServicePrefixes(svc, advert, ls)
			if err != nil {
				return nil, err
			}

			for _, prefix := range desiredPrefixes {
				path, pathKey, err := r.srv6Paths.GetSRv6VPNPath(prefix, bgpVRF)
				if err != nil {
					return nil, err
				}
				path.Family = agentFamily

				// we only support ipv4/mpls_vpn address family
				if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
					reconcilerv2.AddPathToAFPathsMap(desiredFamilyPaths, agentFamily, path, pathKey)
				}
			}
		}
	}
	return desiredFamilyPaths, nil
}

// Populate locally available services used for externalTrafficPolicy=local handling
func (r *ServiceVRFReconciler) populateLocalServices(localNodeName string) (sets.Set[resource.Key], error) {
	ls := sets.New[resource.Key]()

	epList, err := r.epDiffStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list EPs from diffstore: %w", err)
	}

endpointsLoop:
	for _, eps := range epList {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from EPs. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
			// We only care about LoadBalancer services.
			continue
		}

		svcKey := resource.Key{
			Name:      eps.ServiceID.Name,
			Namespace: eps.ServiceID.Namespace,
		}

		for _, be := range eps.Backends {
			if !be.Terminating && be.NodeName == localNodeName {
				// At least one endpoint is available on this node. We
				// can add service to the local services set.
				ls.Insert(svcKey)
				continue endpointsLoop
			}
		}
	}

	return ls, nil
}

func hasLocalEndpoints(svc *slim_corev1.Service, ls sets.Set[resource.Key]) bool {
	return ls.Has(resource.Key{Name: svc.GetName(), Namespace: svc.GetNamespace()})
}

func (r *ServiceVRFReconciler) resolveSvcFromEndpoints(eps *k8s.Endpoints) (*slim_corev1.Service, bool, error) {
	k := resource.Key{
		Name:      eps.ServiceID.Name,
		Namespace: eps.ServiceID.Namespace,
	}
	return r.svcDiffStore.GetByKey(k)
}

// configModified checks if the any of the following configurations have modified
// BGP advertisements, BGP VRF configurations, SID info for VRFs
func (r *ServiceVRFReconciler) configModified(iParams EnterpriseReconcileParams, desiredVRFAdverts VRFAdvertisements, desiredVRFSIDInfo VRFSIDInfo) bool {
	currentMetadata := r.getMetadata(iParams.BGPInstance)

	return !VRFAdvertisementsEqual(currentMetadata.vrfAdverts, desiredVRFAdverts) ||
		!r.vrfConfigsEqual(currentMetadata.vrfConfigs, iParams.DesiredConfig.VRFs) ||
		!r.vrfSIDInfoEqual(currentMetadata.vrfSIDs, desiredVRFSIDInfo)
}

func (r *ServiceVRFReconciler) vrfConfigsEqual(firstVRFs, secondVRFs []v1alpha1.IsovalentBGPNodeVRF) bool {
	if len(firstVRFs) != len(secondVRFs) {
		return false
	}

	for _, firstVRF := range firstVRFs {
		found := true
		for _, secondVRF := range secondVRFs {
			if firstVRF.VRFRef == secondVRF.VRFRef {
				found = true
				if !firstVRF.DeepEqual(&secondVRF) {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (r *ServiceVRFReconciler) vrfSIDInfoEqual(firstVRFs, secondVRFs VRFSIDInfo) bool {
	if len(firstVRFs) != len(secondVRFs) {
		return false
	}

	for vrf, firstSIDInfo := range firstVRFs {
		secondSIDInfo, exists := secondVRFs[vrf]
		if !exists {
			return false
		}

		if !firstSIDInfo.SIDAndBehaviorEqual(secondSIDInfo) {
			return false
		}
	}

	return true
}

func (r *ServiceVRFReconciler) getServicePrefixes(svc *slim_corev1.Service, advert v1alpha1.BGPAdvertisement, ls sets.Set[resource.Key]) ([]netip.Prefix, error) {
	if advert.AdvertisementType != v1alpha1.BGPServiceAdvert {
		return nil, fmt.Errorf("BUG: unexpected advertisement type: %s", advert.AdvertisementType)
	}

	if advert.Selector == nil || advert.Service == nil {
		// advertisement has no selector or no service options, default behavior is not to match any service.
		return nil, nil
	}

	// The instance has a service selector, so determine the desired routes.
	svcSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}

	// Ignore non matching services.
	if !svcSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	var desiredRoutes []netip.Prefix
	// Loop over the service upsertAdverts and determine the desired routes.
	for _, svcAdv := range advert.Service.Addresses {
		if svcAdv == v2alpha1.BGPLoadBalancerIPAddr {
			desiredRoutes = append(desiredRoutes, r.getETPLocalLBSvcPaths(svc, ls)...)
		}
	}

	return desiredRoutes, nil
}

func (r *ServiceVRFReconciler) getETPLocalLBSvcPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key]) []netip.Prefix {
	var desiredPrefixes []netip.Prefix
	if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return desiredPrefixes
	}

	// Ignore externalTrafficPolicy other than local. Current SRv6 datapath does not support eTP cluster.
	if svc.Spec.ExternalTrafficPolicy != slim_corev1.ServiceExternalTrafficPolicyLocal {
		return desiredPrefixes
	}

	// Ignore if there is no local EPs.
	if !hasLocalEndpoints(svc, ls) {
		return desiredPrefixes
	}

	// Ignore service managed by an unsupported LB class.
	if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != v2alpha1.BGPLoadBalancerClass {
		// The service is managed by a different LB class.
		return desiredPrefixes
	}

	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(ingress.IP)
		if err != nil {
			continue
		}
		desiredPrefixes = append(desiredPrefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return desiredPrefixes
}

func (r *ServiceVRFReconciler) getConfiguredSIDInfo(bgpConfig *v1alpha1.IsovalentBGPNodeInstance) (VRFSIDInfo, error) {
	desiredVRFSIDInfo := make(VRFSIDInfo)
	for _, bgpVRF := range bgpConfig.VRFs {
		vrfInfo, exists := r.srv6Manager.GetVRFByName(k8stypes.NamespacedName{Name: bgpVRF.VRFRef})
		if !exists {
			r.logger.Debug("VRF %s not found in SRv6 Manager", bgpVRF.VRFRef)
			continue
		}
		desiredVRFSIDInfo[bgpVRF.VRFRef] = vrfInfo.SIDInfo
	}
	return desiredVRFSIDInfo, nil
}

func serviceLabelSet(svc *slim_corev1.Service) labels.Labels {
	svcLabels := maps.Clone(svc.Labels)
	if svcLabels == nil {
		svcLabels = make(map[string]string)
	}
	svcLabels["io.kubernetes.service.name"] = svc.Name
	svcLabels["io.kubernetes.service.namespace"] = svc.Namespace
	return labels.Set(svcLabels)
}

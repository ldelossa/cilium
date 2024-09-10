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
	"fmt"
	"net/netip"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	enterpriseannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	ossreconcilerv2 "github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/service"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
)

const (
	// svcHealthAdvertiseThresholdDefault defines the default threshold in minimal number of healthy backends,
	// when service routes will be advertised by the BGP Control Plane.
	svcHealthAdvertiseThresholdDefault = 1
)

// ServiceReconciler is an enterprise version of the OSS ServiceReconciler,
// which extends its functionality with enterprise-only features.
// If enabled, the enterprise reconciler is called upon each Reconcile() instead of the OSS reconciler
// (thanks to the same reconciler name and higher priority).
// The Enterprise reconciler calls the OSS reconciler's methods on various places to avoid code duplication.
type ServiceReconciler struct {
	mutex  lock.Mutex
	logger logrus.FieldLogger

	cfg      Config
	signaler *signaler.BGPCPSignaler

	// ossServiceReconciler holds the reference to the OSS ServiceReconciler,
	// set up in WireServiceReconcilers to avoid reconciler dependency loop
	ossServiceReconciler *ossreconcilerv2.ServiceReconciler

	// service health-checker
	healthChecker          service.ServiceHealthCheckManager
	healthCheckerCtxCancel context.CancelFunc

	// internal service health state
	svcHealth        map[k8s.ServiceID]svcFrontendHealthMap // local cache of service health metadata
	svcHealthChanged map[uint32]map[k8s.ServiceID]struct{}  // instance-specific tracker of services with modified health since last reconciliation
}

type ServiceReconcilerOut struct {
	cell.Out

	Reconciler ossreconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type ServiceReconcilerIn struct {
	cell.In
	Lifecycle cell.Lifecycle

	Cfg                Config
	Logger             logrus.FieldLogger
	Signaler           *signaler.BGPCPSignaler
	HealthCheckManager service.ServiceHealthCheckManager
}

// svcFrontendHealth keeps health information about a service frontend, as received from the service health-checker
type svcFrontendHealth struct {
	frontendAddr   loadbalancer.L3n4Addr  // frontend address (one service can have multiple frontend addresses)
	activeBackends []loadbalancer.Backend // current list of active (healthy) backends of the frontend
}

// svcFrontendHealthMap is a map of service frontend health information keyed by the frontend address
type svcFrontendHealthMap map[loadbalancer.L3n4Addr]*svcFrontendHealth

func NewServiceReconciler(in ServiceReconcilerIn) ServiceReconcilerOut {
	if !in.Cfg.SvcHealthCheckingEnabled {
		// ATM, this reconciler is used only when service health checking integration is enabled.
		// If not, this reconciler does not need to run at all - the OSS ServiceReconciler will be used instead.
		return ServiceReconcilerOut{}
	}

	r := &ServiceReconciler{
		logger:           in.Logger,
		cfg:              in.Cfg,
		signaler:         in.Signaler,
		healthChecker:    in.HealthCheckManager,
		svcHealth:        make(map[k8s.ServiceID]svcFrontendHealthMap),
		svcHealthChanged: make(map[uint32]map[k8s.ServiceID]struct{}),
	}
	in.Lifecycle.Append(r)

	return ServiceReconcilerOut{
		Reconciler: r,
	}
}

type WireServiceReconcilersParams struct {
	cell.In

	Cfg         Config
	Reconcilers []ossreconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

// WireServiceReconcilers wires OSS ServiceReconciler dependency in the CEE ServiceReconciler.
// To be called from cell's Invoke function to avoid reconciler dependency loop.
func WireServiceReconcilers(in WireServiceReconcilersParams) error {
	if !in.Cfg.SvcHealthCheckingEnabled {
		return nil
	}
	var (
		ossServiceReconciler *ossreconcilerv2.ServiceReconciler
		ceeServiceReconciler *ServiceReconciler
	)
	for _, configReconciler := range in.Reconcilers {
		switch r := configReconciler.(type) {
		case *ossreconcilerv2.ServiceReconciler:
			ossServiceReconciler = r
		case *ServiceReconciler:
			ceeServiceReconciler = r
		}
		if ossServiceReconciler != nil && ceeServiceReconciler != nil {
			break
		}
	}
	if ossServiceReconciler == nil {
		return fmt.Errorf("couldn't find OSS ServiceReconciler")
	}
	if ceeServiceReconciler == nil {
		return fmt.Errorf("couldn't find CEE ServiceReconciler")
	}
	ceeServiceReconciler.ossServiceReconciler = ossServiceReconciler
	return nil
}

func (r *ServiceReconciler) Name() string {
	return r.ossServiceReconciler.Name() // needs to match the name of the OSS recocniler we are overriding
}

func (r *ServiceReconciler) Priority() int {
	return r.ossServiceReconciler.Priority() - 1 // must be lower (higher priority) than the OSS recocniler we are overriding
}

// Start is a hive lifecycle hook called when running the hive.
func (r *ServiceReconciler) Start(ctx cell.HookContext) error {
	r.mutex.Lock()

	// subscribe to service health-checker updates
	if r.cfg.SvcHealthCheckingEnabled && r.healthChecker != nil {
		// create a new context that will be valid for the whole controller lifetime
		var healthCheckerCtx context.Context
		healthCheckerCtx, r.healthCheckerCtxCancel = context.WithCancel(context.Background())
		r.mutex.Unlock()
		r.healthChecker.Subscribe(healthCheckerCtx, r.ServiceHealthUpdate)
	} else {
		r.mutex.Unlock()
	}
	return nil
}

// Stop is a hive lifecycle hook called when stopping the hive.
func (r *ServiceReconciler) Stop(ctx cell.HookContext) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// unsubscribe from service health-checker
	if r.cfg.SvcHealthCheckingEnabled && r.healthCheckerCtxCancel != nil {
		r.healthCheckerCtxCancel()
	}
	return nil
}

// Init is called when a new BGP instance is being initialized.
func (r *ServiceReconciler) Init(i *instance.BGPInstance) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if i == nil {
		return fmt.Errorf("BUG: service reconciler initialization with nil BGPInstance")
	}
	// initialize service health tracker map for this instance
	r.svcHealthChanged[i.Global.ASN] = make(map[k8s.ServiceID]struct{})

	// we need to initialize the OSS reconciler ourselves, as it is skipped by the manager
	return r.ossServiceReconciler.Init(i)
}

// Cleanup is called when a new BGP instance is being removed.
func (r *ServiceReconciler) Cleanup(i *instance.BGPInstance) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if i != nil {
		// cleanup service health tracker map for this instance
		delete(r.svcHealthChanged, i.Global.ASN)

		// we need to cleanup the OSS reconciler ourselves, as it is skipped by the manager
		r.ossServiceReconciler.Cleanup(i)
	}
}

// ServiceHealthUpdate is called by the service health-checker upon changes in service health based on backend health-checking.
func (r *ServiceReconciler) ServiceHealthUpdate(svcInfo service.HealthUpdateSvcInfo) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.cfg.SvcHealthCheckingEnabled {
		return // health-checker integration is disabled, nothing to do
	}
	if svcInfo.SvcType != loadbalancer.SVCTypeLoadBalancer || svcInfo.Name.Name == "" {
		return // ignore updates for non-LB svcFrontendsHealth and unknown services
	}
	if svcInfo.Addr.Scope != loadbalancer.ScopeExternal {
		// We are only interested in updates with external address lookup scope.
		// In case of ExternalTraficPolicy == local, these contain only local endpoints, otherwise they contain all endpoints.
		return
	}

	svcID := k8s.ServiceID{Name: svcInfo.Name.Name, Namespace: svcInfo.Name.Namespace, Cluster: svcInfo.Name.Cluster}

	r.logger.WithFields(logrus.Fields{
		types.ServiceIDLogField:      svcID,
		types.ServiceAddressLogField: svcInfo.Addr,
		types.BackendCountLogField:   len(svcInfo.ActiveBackends),
	}).Debug("Service health update")

	svcFrontendsHealth, found := r.svcHealth[svcID]
	if !found {
		svcFrontendsHealth = make(svcFrontendHealthMap)
		r.svcHealth[svcID] = svcFrontendsHealth
	}

	frontendHealth := svcFrontendsHealth[svcInfo.Addr]
	if frontendHealth == nil {
		frontendHealth = &svcFrontendHealth{
			frontendAddr: svcInfo.Addr,
		}
		svcFrontendsHealth[svcInfo.Addr] = frontendHealth
	}

	// update cache of active backends
	frontendHealth.activeBackends = svcInfo.ActiveBackends

	// mark the service for reconciliation
	for _, instanceMap := range r.svcHealthChanged {
		instanceMap[svcID] = struct{}{}
	}
	// trigger a reconciliation
	r.signaler.Event(struct{}{})
}

// Reconcile mirrors the OSS reconciler's Reconcile() code path but calls enterprise-specific reconcileServices().
func (r *ServiceReconciler) Reconcile(ctx context.Context, p ossreconcilerv2.ReconcileParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if p.DesiredConfig == nil {
		return fmt.Errorf("BUG: attempted service reconciliation with nil CiliumBGPNodeConfig")
	}

	if p.CiliumNode == nil {
		return fmt.Errorf("BUG: attempted service reconciliation with nil local CiliumNode")
	}

	r.logger.Debug("Performing CEE Service reconciliation")

	desiredPeerAdverts, err := r.ossServiceReconciler.GetPeerAdvertisement().GetConfiguredAdvertisements(p.DesiredConfig, v2alpha1.BGPServiceAdvert)
	if err != nil {
		return err
	}

	ls, err := r.ossServiceReconciler.PopulateLocalServices(p.CiliumNode.Name)
	if err != nil {
		return fmt.Errorf("failed to populate local services: %w", err)
	}

	// must be done before reconciling paths and policies since it sets metadata with latest desiredPeerAdverts
	reqFullReconcile := r.ossServiceReconciler.ModifiedServiceAdvertisements(p, desiredPeerAdverts)

	err = r.reconcileServices(ctx, p, desiredPeerAdverts, ls, reqFullReconcile)

	if err == nil && reqFullReconcile {
		// update svc advertisements in metadata only if the reconciliation was successful
		r.ossServiceReconciler.UpdateServiceAdvertisementsMetadata(p, desiredPeerAdverts)
	}
	return err
}

// reconcileServices mirrors the OSS reconciler's reconcileServices() code path and applies enterprise-specific
// service reconciliation logic on top of it.
func (r *ServiceReconciler) reconcileServices(ctx context.Context, p ossreconcilerv2.ReconcileParams,
	desiredPeerAdverts ossreconcilerv2.PeerAdvertisements, ls sets.Set[resource.Key], fullReconcile bool) error {
	var (
		toReconcile []*slim_corev1.Service
		toWithdraw  []resource.Key

		desiredSvcRoutePolicies ossreconcilerv2.ResourceRoutePolicyMap
		desiredSvcPaths         ossreconcilerv2.ResourceAFPathsMap

		err error
	)

	if fullReconcile {
		r.logger.Debug("Performing all services reconciliation")

		// get all services to reconcile and to withdraw.
		toReconcile, toWithdraw, err = r.ossServiceReconciler.FullReconciliationServiceList(p)
		if err != nil {
			return err
		}
	} else {
		r.logger.Debug("Performing modified services reconciliation")

		// get modified services to reconcile and to withdraw.
		// Note: we should call svc diff only once in a reconcile loop.
		toReconcile, toWithdraw, err = r.ossServiceReconciler.DiffReconciliationServiceList(p)
		if err != nil {
			return err
		}
	}
	r.logger.WithFields(logrus.Fields{
		types.ToReconcileLogField: len(toReconcile),
		types.ToWithdrawLogField:  len(toWithdraw),
	}).Debug("Reconciling services")

	// get desired service route policies
	desiredSvcRoutePolicies, err = r.ossServiceReconciler.GetDesiredRoutePolicies(p, desiredPeerAdverts, toReconcile, toWithdraw, ls)
	if err != nil {
		return err
	}

	// reconcile service route policies
	err = r.ossServiceReconciler.ReconcileSvcRoutePolicies(ctx, p, desiredSvcRoutePolicies)
	if err != nil {
		return fmt.Errorf("failed to reconcile service route policies: %w", err)
	}

	if r.cfg.SvcHealthCheckingEnabled && !fullReconcile {
		// in case of diff reconciliation, also reconcile services with modified health state
		// NOTE: do not adapt toReconcile before reconciling route policies - removing/adding route policy would cause session reset
		toReconcile = append(toReconcile, r.healthModifiedServices(p)...)

		// we may now have duplicated services in toReconcile, deduplicate
		toReconcile = ciliumslices.Unique(toReconcile)
	}

	// get desired service paths
	desiredSvcPaths, err = r.getDesiredPaths(p, desiredPeerAdverts, toReconcile, toWithdraw, ls)
	if err != nil {
		return err
	}

	// reconcile service paths
	err = r.ossServiceReconciler.ReconcilePaths(ctx, p, desiredSvcPaths)
	if err != nil {
		return fmt.Errorf("failed to reconcile service paths: %w", err)
	}

	if r.cfg.SvcHealthCheckingEnabled {
		// delete the svc from the service-specific health caches
		for _, key := range toWithdraw {
			svcID := k8s.ServiceID{Name: key.Name, Namespace: key.Namespace}
			delete(r.svcHealth, svcID)
			delete(r.svcHealthChanged[p.BGPInstance.Global.ASN], svcID)
		}
	}

	return nil
}

// healthModifiedServices returns a list of services with modified health state since the last call of this method.
func (r *ServiceReconciler) healthModifiedServices(p ossreconcilerv2.ReconcileParams) []*slim_corev1.Service {
	var modified []*slim_corev1.Service

	// Deleting keys doesn't shrink the memory size, so we shrink it by recreating the map
	// if it reaches above the threshold (arbitrary value).
	// Below the threshold we don't recreate the map to avoid unnecessary allocation.
	const shrinkThreshold = 64
	shrink := len(r.svcHealthChanged) > shrinkThreshold

	// loop over services with modified health since last reconciliation
	for svcID := range r.svcHealthChanged[p.BGPInstance.Global.ASN] {
		svc, exists, err := r.getSvcByID(svcID)
		if err != nil {
			r.logger.WithError(err).WithField(types.ServiceIDLogField, svcID).Warn("Could not retrieve service, skipping its reconciliation")
			continue
		}
		if !exists {
			continue // svc not found (may have been deleted already), nothing to do
		}
		modified = append(modified, svc)
		if !shrink {
			delete(r.svcHealthChanged[p.BGPInstance.Global.ASN], svcID)
		}
	}

	if shrink {
		// re-create the health tracking map
		r.svcHealthChanged[p.BGPInstance.Global.ASN] = make(map[k8s.ServiceID]struct{})
	}
	return modified
}

// getDesiredPaths mirrors the OSS reconciler's getDesiredPaths() method, but calls the enterprise
// version of getServiceAFPaths().
func (r *ServiceReconciler) getDesiredPaths(p ossreconcilerv2.ReconcileParams, desiredPeerAdverts ossreconcilerv2.PeerAdvertisements,
	toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, ls sets.Set[resource.Key]) (ossreconcilerv2.ResourceAFPathsMap, error) {

	desiredServiceAFPaths := make(ossreconcilerv2.ResourceAFPathsMap)
	for _, svc := range toReconcile {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		afPaths, err := r.getServiceAFPaths(p, desiredPeerAdverts, svc, ls)
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

// getServiceAFPaths applies enterprise-specific filtering for paths that should be advertised for a service.
func (r *ServiceReconciler) getServiceAFPaths(p ossreconcilerv2.ReconcileParams, desiredPeerAdverts ossreconcilerv2.PeerAdvertisements,
	svc *slim_corev1.Service, ls sets.Set[resource.Key]) (ossreconcilerv2.AFPathsMap, error) {

	// the service with no-advertisement annotation should not be announced
	if r.svcHasNoAdvertisementAnnotations(svc) {
		return nil, nil
	}

	// retrieve all service paths to advertise from the OSS reconciler
	desiredFamilyAdverts, err := r.ossServiceReconciler.GetServiceAFPaths(p, desiredPeerAdverts, svc, ls)
	if err != nil {
		return nil, err
	}

	// ignore service frontends with no healthy backends
	if r.cfg.SvcHealthCheckingEnabled {
		for _, pathMap := range desiredFamilyAdverts {
			for path := range pathMap {
				prefix, err := netip.ParsePrefix(path)
				if err != nil {
					return nil, fmt.Errorf("invalid service advertisement path %s: %w", path, err)
				}
				if !r.svcFrontendHealthy(svc, prefix.Addr()) {
					// delete the route to frontend with non-healthy backends from desired advertisements
					delete(pathMap, path)
				}
			}
		}
	}

	return desiredFamilyAdverts, nil
}

// svcFrontendHealthy checks whether a service frontend is considered healthy based on the cached health state.
func (r *ServiceReconciler) svcFrontendHealthy(svc *slim_corev1.Service, frontendIP netip.Addr) bool {
	// if the hc probe interval annotation is not set on the service, it means that health-checking is not enabled
	// for the service, and it is considered to be always healthy
	if _, exists := annotation.Get(svc, enterpriseannotation.ServiceHealthProbeInterval); !exists {
		return true
	}

	// retrieve service health state
	svcID := k8s.ParseServiceID(svc)
	feHealth, found := r.svcHealth[svcID]
	if !found {
		// if there is no health info for the service (yet), we assume it is healthy
		return true
	}

	// determine service's health check advertise threshold
	threshold := svcHealthAdvertiseThresholdDefault
	if annVal, ok := annotation.Get(svc, enterpriseannotation.ServiceHealthBGPAdvertiseThreshold); ok {
		if val, err := strconv.Atoi(annVal); err == nil {
			threshold = val
		}
	}

	// compile service port set
	svcPorts := sets.New[loadbalancer.L4Addr]()
	for _, svcPort := range svc.Spec.Ports {
		svcPorts.Insert(loadbalancer.L4Addr{Protocol: svcProtocolToLBL4Type(svcPort.Protocol), Port: uint16(svcPort.Port)})
	}

	// loop over all service frontend addresses with known health state
	for _, fe := range feHealth {
		// ignore frontends with non-matching frontend address
		// (e.g. in case of dual-stack with an IPv4 and IPv6 frontend, only consider proper address family)
		if fe.frontendAddr.AddrCluster.Addr() != frontendIP {
			continue
		}
		// ignore frontends with non-matching L4 proto / port
		// (e.g. ignore stale frontend health after removing a service port)
		if !svcPorts.Has(fe.frontendAddr.L4Addr) {
			continue
		}
		// if for any frontend we do not have enough backends, we declare the service as not healthy
		// (e.g. in case of two service ports: one healthy and one unhealthy, the service is considered unhealthy)
		if len(fe.activeBackends) < threshold {
			return false
		}
	}
	return true
}

// svcHasNoAdvertisementAnnotations checks whether a service has no-advertisement annotations set
func (r *ServiceReconciler) svcHasNoAdvertisementAnnotations(svc *slim_corev1.Service) bool {
	if _, exists := annotation.Get(svc, enterpriseannotation.ServiceNoAdvertisement); exists {
		return true
	}
	return false
}

// getSvcByID retrieves a service by the provided service ID.
func (r *ServiceReconciler) getSvcByID(svcID k8s.ServiceID) (*slim_corev1.Service, bool, error) {
	key := resource.Key{
		Name:      svcID.Name,
		Namespace: svcID.Namespace,
	}
	return r.ossServiceReconciler.GetService(key)
}

func svcProtocolToLBL4Type(svcProto slim_corev1.Protocol) loadbalancer.L4Type {
	switch svcProto {
	case slim_corev1.ProtocolUDP:
		return loadbalancer.UDP
	case slim_corev1.ProtocolSCTP:
		return loadbalancer.SCTP
	default:
		return loadbalancer.TCP
	}
}

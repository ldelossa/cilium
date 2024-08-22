// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconciler

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	enterpriseannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	ossreconciler "github.com/cilium/cilium/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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

// lbServiceReconciler is an enterprise version of the OSS lbServiceReconciler,
// which extends its functionality with enterprise-only features.
// If enabled, the enterprise reconciler is called upon each Reconcile() instead of the OSS reconciler
// (thanks to the same reconciler name and higher priority).
// The Enterprise reconciler calls the OSS reconciler's methods on various places to avoid code duplication.
type lbServiceReconciler struct {
	mutex lock.Mutex // to ensure that ServiceHealthUpdate() and Reconcile() are not processed concurrently
	log   *logrus.Entry

	cfg      Config
	signaler *signaler.BGPCPSignaler

	// ossLBServiceReconciler holds the reference to the OSS LBServiceReconciler,
	// set up in WireServiceReconcilers to avoid reconciler dependency loop
	ossLBServiceReconciler *ossreconciler.ServiceReconciler

	// service health-checker
	healthChecker    service.ServiceHealthCheckManager
	healthCheckerCtx context.Context

	// internal service health state
	svcHealth        map[k8s.ServiceID]svcFrontendHealthMap // local cache of service health metadata
	svcHealthChanged map[k8s.ServiceID]struct{}             // tracks services with modified health since last reconciliation
}

type lbServiceReconcilerParams struct {
	cell.In
	Lifecycle cell.Lifecycle

	Cfg                Config
	Signaler           *signaler.BGPCPSignaler
	HealthCheckManager service.ServiceHealthCheckManager
}

type lbServiceReconcilerOut struct {
	cell.Out

	Reconciler ossreconciler.ConfigReconciler `group:"bgp-config-reconciler"`
}

// svcFrontendHealth keeps health information about a service frontend, as received from the service health-checker
type svcFrontendHealth struct {
	frontendAddr   loadbalancer.L3n4Addr  // frontend address (one service can have multiple frontend addresses)
	activeBackends []loadbalancer.Backend // current list of active (healthy) backends of the frontend
}

// svcFrontendHealthMap is a map of service frontend health information keyed by the frontend address
type svcFrontendHealthMap map[loadbalancer.L3n4Addr]*svcFrontendHealth

func newLBServiceReconciler(p lbServiceReconcilerParams) lbServiceReconcilerOut {
	if !p.Cfg.SvcHealthCheckingEnabled {
		// ATM, this reconciler is used only when service health checking integration is enabled.
		// If not, this reconciler does not need to run at all - the OSS LBServiceReconciler will be used instead.
		return lbServiceReconcilerOut{}
	}
	r := &lbServiceReconciler{
		cfg:              p.Cfg,
		signaler:         p.Signaler,
		healthChecker:    p.HealthCheckManager,
		svcHealth:        make(map[k8s.ServiceID]svcFrontendHealthMap),
		svcHealthChanged: make(map[k8s.ServiceID]struct{}),
	}
	r.log = log.WithFields(logrus.Fields{"component": r.Name()})
	p.Lifecycle.Append(r)
	return lbServiceReconcilerOut{
		Reconciler: r,
	}
}

type WireLBServiceReconcilersParams struct {
	cell.In

	Cfg               Config
	ConfigReconcilers []ossreconciler.ConfigReconciler `group:"bgp-config-reconciler"`
}

// wireLBServiceReconcilers wires OSS LBServiceReconciler dependency in LBServiceReconciler.
// To be called from cell's Invoke function to avoid reconciler dependency loop.
func wireLBServiceReconcilers(p WireLBServiceReconcilersParams) error {
	if !p.Cfg.SvcHealthCheckingEnabled {
		return nil
	}
	var (
		ossLBServiceReconciler *ossreconciler.ServiceReconciler
		ceeLBServiceReconciler *lbServiceReconciler
	)
	for _, configReconciler := range p.ConfigReconcilers {
		switch r := configReconciler.(type) {
		case *ossreconciler.ServiceReconciler:
			ossLBServiceReconciler = r
		case *lbServiceReconciler:
			ceeLBServiceReconciler = r
		}
		if ossLBServiceReconciler != nil && ceeLBServiceReconciler != nil {
			break
		}
	}
	if ossLBServiceReconciler == nil {
		return fmt.Errorf("couldn't find LBServiceReconciler")
	}
	if ceeLBServiceReconciler == nil {
		return fmt.Errorf("couldn't find LBServiceReconciler")
	}
	ceeLBServiceReconciler.ossLBServiceReconciler = ossLBServiceReconciler
	return nil
}

func (r *lbServiceReconciler) Name() string {
	return r.ossLBServiceReconciler.Name() // needs to match the name of the OSS recocniler we are overriding
}

func (r *lbServiceReconciler) Priority() int {
	return r.ossLBServiceReconciler.Priority() - 1 // must be lower (higher priority) than the OSS recocniler we are overriding
}

func (r *lbServiceReconciler) Init(_ *instance.ServerWithConfig) error {
	return nil
}

func (r *lbServiceReconciler) Cleanup(_ *instance.ServerWithConfig) {}

// Start is a hive lifecycle hook called when running the hive.
func (r *lbServiceReconciler) Start(ctx cell.HookContext) error {
	r.mutex.Lock()

	// subscribe to service health-checker updates
	if r.cfg.SvcHealthCheckingEnabled && r.healthChecker != nil {
		r.healthCheckerCtx = context.Background() // we need a new context that will be valid for the whole controller lifetime
		r.mutex.Unlock()
		r.healthChecker.Subscribe(r.healthCheckerCtx, r.ServiceHealthUpdate)
	} else {
		r.mutex.Unlock()
	}
	return nil
}

// Stop is a hive lifecycle hook called when stopping the hive.
func (r *lbServiceReconciler) Stop(ctx cell.HookContext) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// unsubscribe from service health-checker
	if r.cfg.SvcHealthCheckingEnabled && r.healthCheckerCtx != nil {
		r.healthCheckerCtx.Done()
	}
	return nil
}

// ServiceHealthUpdate is called by the service health-checker upon changes in service health based on backend health-checking.
func (r *lbServiceReconciler) ServiceHealthUpdate(svcInfo service.HealthUpdateSvcInfo) {
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
	r.log.WithFields(logrus.Fields{"service": svcID, "backends": len(svcInfo.ActiveBackends)}).Debugf("Service health update")

	svcFrontendsHealth := r.svcHealth[svcID]
	if svcFrontendsHealth == nil {
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
	r.svcHealthChanged[svcID] = struct{}{}
	// trigger a reconciliation
	r.signaler.Event(struct{}{})
}

// Reconcile is called by the BGP Manager whenever a reconciliation has been triggered.
func (r *lbServiceReconciler) Reconcile(ctx context.Context, p ossreconciler.ReconcileParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if p.CiliumNode == nil {
		return fmt.Errorf("attempted load balancer service reconciliation with nil local CiliumNode")
	}
	if r.ossLBServiceReconciler == nil {
		return fmt.Errorf("attempted enterprise service reconciliation with nil local ossLBServiceReconciler")
	}

	ls, err := r.ossLBServiceReconciler.PopulateLocalServices(p.CiliumNode.Name)
	if err != nil {
		return err
	}

	if r.ossLBServiceReconciler.RequiresFullReconciliation(p) {
		return r.fullReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls)
	}
	return r.svcDiffReconciliation(ctx, p.CurrentServer, p.DesiredConfig, ls)
}

// fullReconciliation reconciles all services, should be called only when diff reconciliation is not possible.
func (r *lbServiceReconciler) fullReconciliation(ctx context.Context, sc *instance.ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls ossreconciler.LocalServices) error {
	toReconcile, toWithdraw, err := r.ossLBServiceReconciler.FullReconciliationServiceList(sc)
	if err != nil {
		return err
	}

	r.log.WithFields(logrus.Fields{"toReconcile": len(toReconcile), "toWithdraw": len(toWithdraw)}).Debug("Full service reconciliation")

	for _, svc := range toReconcile {
		if err := r.reconcileService(ctx, sc, newc, svc, ls); err != nil {
			return fmt.Errorf("failed to reconcile service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
	}
	for _, svc := range toWithdraw {
		if err := r.withdrawService(ctx, sc, svc); err != nil {
			return fmt.Errorf("failed to withdraw service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
	}
	return nil
}

// svcDiffReconciliation performs reconciliation, only on services which have been created, updated or deleted
// since the last diff reconciliation.
func (r *lbServiceReconciler) svcDiffReconciliation(ctx context.Context, sc *instance.ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, ls ossreconciler.LocalServices) error {
	toReconcile, toWithdraw, err := r.ossLBServiceReconciler.DiffReconciliationServiceList(sc)
	if err != nil {
		return err
	}

	if r.cfg.SvcHealthCheckingEnabled {
		// reconcile services with modified health state
		toReconcile = append(toReconcile, r.healthModifiedServices()...)
	}

	// we may have duplicated services now in toReconcile, deduplicate
	toReconcileDeduped := ciliumslices.UniqueFunc(
		toReconcile,
		func(i int) resource.Key {
			return resource.Key{
				Name:      toReconcile[i].GetName(),
				Namespace: toReconcile[i].GetNamespace(),
			}
		},
	)

	r.log.WithFields(logrus.Fields{"toReconcile": len(toReconcileDeduped), "toWithdraw": len(toWithdraw)}).Debug("Diff service reconciliation")

	for _, svc := range toReconcileDeduped {
		if err := r.reconcileService(ctx, sc, newc, svc, ls); err != nil {
			return fmt.Errorf("failed to reconcile service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
	}

	for _, svcKey := range toWithdraw {
		if err := r.withdrawService(ctx, sc, svcKey); err != nil {
			return fmt.Errorf("failed to withdraw service %s: %w", svcKey, err)
		}
	}
	return nil
}

func (r *lbServiceReconciler) svcDesiredRoutes(newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls ossreconciler.LocalServices) ([]netip.Prefix, error) {
	// The service with no-advertisement annotation should not be announced
	if r.svcHasNoAdvertisementAnnotations(svc) {
		return []netip.Prefix{}, nil
	}

	desiredRoutes, err := r.ossLBServiceReconciler.SvcDesiredRoutes(newc, svc, ls)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve svc desired routes: %w", err)
	}

	// ignore service frontends with no healthy backends
	if r.cfg.SvcHealthCheckingEnabled {
		// loop over desiredRoutes in reverse order, so we can delete entries without effecting iteration
		for i := len(desiredRoutes) - 1; i >= 0; i-- {
			if !r.svcFrontendHealthy(svc, desiredRoutes[i].Addr()) {
				// delete the route to frontend with non-healthy backends from desiredRoutes
				desiredRoutes = slices.Delete(desiredRoutes, i, i+1)
			}
		}
	}

	return desiredRoutes, nil
}

// reconcileService gets the desired routes of a given service and makes sure that is what is being announced.
func (r *lbServiceReconciler) reconcileService(ctx context.Context, sc *instance.ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls ossreconciler.LocalServices) error {
	desiredRoutes, err := r.svcDesiredRoutes(newc, svc, ls)
	if err != nil {
		return err
	}
	return r.ossLBServiceReconciler.ReconcileServiceRoutes(ctx, sc, svc, desiredRoutes)
}

// withdrawService withdraws all announced routes of a service, to be called when a service is deleted.
func (r *lbServiceReconciler) withdrawService(ctx context.Context, sc *instance.ServerWithConfig, key resource.Key) error {
	// delete the svc from service health caches
	if r.cfg.SvcHealthCheckingEnabled {
		svcID := k8s.ServiceID{Name: key.Name, Namespace: key.Namespace}
		delete(r.svcHealth, svcID)
		delete(r.svcHealthChanged, svcID)
	}
	return r.ossLBServiceReconciler.WithdrawService(ctx, sc, key)
}

// healthModifiedServices returns a list of services with modified health state since the last call of this method.
func (r *lbServiceReconciler) healthModifiedServices() []*slim_corev1.Service {
	var modified []*slim_corev1.Service

	// Deleting keys doesn't shrink the memory size, so we shrink it by recreating the map
	// if it reaches above the threshold (arbitrary value).
	// Below the threshold we don't recreate the map to avoid unnecessary allocation.
	const shrinkThreshold = 64
	shrink := len(r.svcHealthChanged) > shrinkThreshold

	// loop over services with modified health since last reconciliation
	for svcID := range r.svcHealthChanged {
		svc, exists, err := r.getSvcByID(svcID)
		if !exists {
			continue // svc not found (may have been deleted already), nothing to do
		}
		if err != nil {
			r.log.WithError(err).WithFields(logrus.Fields{"service": svcID}).Warn("Could not retrieve service, skipping its reconciliation")
			continue
		}
		modified = append(modified, svc)
		if !shrink {
			delete(r.svcHealthChanged, svcID)
		}
	}

	if shrink {
		// re-create the health tracking map
		r.svcHealthChanged = make(map[k8s.ServiceID]struct{})
	}
	return modified
}

// svcFrontendHealthy checks whether a service frontend is considered healthy based on the cached health state.
func (r *lbServiceReconciler) svcFrontendHealthy(svc *slim_corev1.Service, frontendIP netip.Addr) bool {
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

	// loop over all service frontend addresses with known health state
	for _, fe := range feHealth {
		if fe.frontendAddr.AddrCluster.Addr() != frontendIP {
			// ignore frontends with non-matching frontend address
			// (e.g. in case of dual-stack with an IPv4 and IPv6 frontend, only consider proper address family)
			continue
		}
		if len(fe.activeBackends) < threshold {
			// if for any frontend we do not have enough backends, we declare the service as not healthy
			// (e.g. in case of two service ports: one healthy and one unhealthy, the service is considered unhealthy)
			return false
		}
	}
	return true
}

// svcHasNoAdvertisementAnnotations checks whether a service has no-advertisement annotations set
func (r *lbServiceReconciler) svcHasNoAdvertisementAnnotations(svc *slim_corev1.Service) bool {
	if _, exists := annotation.Get(svc, enterpriseannotation.ServiceNoAdvertisement); exists {
		return true
	}
	return false
}

// getSvcByID retrieves a service by the provided service ID.
func (r *lbServiceReconciler) getSvcByID(svcID k8s.ServiceID) (*slim_corev1.Service, bool, error) {
	key := resource.Key{
		Name:      svcID.Name,
		Namespace: svcID.Namespace,
	}
	return r.ossLBServiceReconciler.GetService(key)
}

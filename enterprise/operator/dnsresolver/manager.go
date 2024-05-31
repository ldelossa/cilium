//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/operator/dnsclient"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

// manager is responsible for handling IsovalentFQDNGroup events. It will spin
// up resolvers and reconcilers to handle each instance of an
// IsovalentFQDNGroup.
type manager struct {
	logger logrus.FieldLogger

	shutdowner hive.Shutdowner

	clientset cilium_client_v2alpha1.CiliumCIDRGroupInterface
	fqdnGroup resource.Resource[*v1alpha1.IsovalentFQDNGroup]

	ctrMgr *controller.Manager

	dnsClient   dnsclient.Resolver
	minInterval time.Duration

	// fqdn -> resolver
	resolvers map[string]*resolver
	// fqdnGroup -> cidr group reconciler
	reconcilers map[string]*reconciler

	// cache contains the mappings between IsovalentFQDNGroups and their FQDNs.
	cache status

	store *fqdnStore

	wp *workerpool.WorkerPool

	metrics *Metrics
}

func newManager(params resolverManagerParams) *manager {
	if !params.Clientset.IsEnabled() {
		return nil
	}

	mgr := &manager{
		logger:      params.Logger,
		shutdowner:  params.Shutdowner,
		clientset:   params.Clientset.CiliumV2alpha1().CiliumCIDRGroups(),
		fqdnGroup:   params.FQDNGroupResource,
		ctrMgr:      controller.NewManager(),
		dnsClient:   params.DNSClient,
		minInterval: params.Cfg.FQDNGroupMinQueryInterval,
		resolvers:   make(map[string]*resolver),
		reconcilers: make(map[string]*reconciler),
		cache:       make(status),
		store:       newStore(),
		wp:          workerpool.New(1),
		metrics:     params.Metrics,
	}
	params.LC.Append(mgr)

	return mgr
}

func (mgr *manager) Start(cell.HookContext) error {
	return mgr.wp.Submit("dns-resolvers-manager", mgr.run)
}

func (mgr *manager) Stop(cell.HookContext) error {
	if err := mgr.wp.Close(); err != nil {
		return err
	}

	return nil
}

func (mgr *manager) run(ctx context.Context) error {
	for event := range mgr.fqdnGroup.Events(ctx) {
		var err error
		switch event.Kind {
		case resource.Upsert:
			err = mgr.onUpdate(ctx, event.Object)
		case resource.Delete:
			err = mgr.onDelete(ctx, event.Object)
		}

		if err != nil {
			mgr.logger.WithFields(logrus.Fields{
				"fqdnGroup": event.Object.Name,
				"eventType": event.Kind,
			}).WithError(err).Warning("Error while handling IsovalentFQDNGroup event, will retry")
		}

		event.Done(err)
	}

	var errs []error
	for _, resolver := range mgr.resolvers {
		if err := resolver.stop(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, reconciler := range mgr.reconcilers {
		if err := reconciler.stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	mgr.ctrMgr.RemoveAllAndWait()

	return nil
}

func (mgr *manager) onUpdate(ctx context.Context, obj *v1alpha1.IsovalentFQDNGroup) error {
	// wrap the deferred Set into a naked func() to correctly evaluate len(mgr.reconcilers)
	defer func() { mgr.metrics.FQDNGroupReconcilers.Set(float64(len(mgr.reconcilers))) }()

	fqdnGroup := obj.Name
	mgr.logger.WithField("fqdnGroup", fqdnGroup).Debug(
		"resyncing streams and restarting cidr group reconciler",
	)

	fqdns := toStrings(obj.Spec.FQDNs)
	if err := mgr.syncResolvers(fqdnGroup, fqdns); err != nil {
		return fmt.Errorf("failed to sync resolvers on FQDNGroup %s update: %w", fqdnGroup, err)
	}

	// stop the old reconciler and start a new one listening to notifications
	// related to the updated FQDNGroup
	if reconciler, ok := mgr.reconcilers[fqdnGroup]; ok {
		if err := reconciler.stop(); err != nil {
			return fmt.Errorf("failed to close reconciler on FQDNGroup %s update: %w", fqdnGroup, err)
		}
	}
	reconciler := newReconciler(
		mgr.logger,
		fqdnGroup,
		obj.GetUID(),
		fqdns,
		mgr.clientset,
		mgr.ctrMgr,
		mgr.store,
	)
	if err := reconciler.start(); err != nil {
		return fmt.Errorf("failed to run reconciler on FQDNGroup %s update: %w", fqdnGroup, err)
	}

	// update internal mgr cache
	mgr.cache[fqdnGroup] = fqdns
	mgr.reconcilers[fqdnGroup] = reconciler

	return nil
}

func (mgr *manager) onDelete(ctx context.Context, obj *v1alpha1.IsovalentFQDNGroup) error {
	// wrap the deferred Set into a naked func() to correctly evaluate len(mgr.reconcilers)
	defer func() { mgr.metrics.FQDNGroupReconcilers.Set(float64(len(mgr.reconcilers))) }()

	fqdnGroup := obj.Name
	mgr.logger.WithField("fqdnGroup", fqdnGroup).Debug(
		"deleting streams and cidr group reconciler",
	)

	if reconciler, ok := mgr.reconcilers[fqdnGroup]; ok {
		if err := reconciler.stop(); err != nil {
			return fmt.Errorf("failed to close reconciler on FQDNGroup %s delete: %w", fqdnGroup, err)
		}
	}

	if err := mgr.ctrMgr.RemoveController(fqdnGroup); err != nil {
		return fmt.Errorf("failed to remove reconciler FQDNGroup %s controller: %w", fqdnGroup, err)
	}

	if err := mgr.syncResolvers(fqdnGroup, nil); err != nil {
		return fmt.Errorf("failed to sync resolvers on FQDNGroup %s delete: %w", fqdnGroup, err)
	}

	// update internal mgr cache
	delete(mgr.cache, fqdnGroup)
	delete(mgr.reconcilers, fqdnGroup)

	return nil
}

func toStrings(objFQDNs []v1alpha1.FQDN) []string {
	fqdns := make([]string, 0, len(objFQDNs))
	for _, fqdn := range objFQDNs {
		fqdns = append(fqdns, string(fqdn))
	}
	return fqdns
}

func (mgr *manager) syncResolvers(fqdnGroup string, fqdns []string) error {
	// wrap the deferred Set into a naked func() to correctly evaluate len(mgr.reconcilers)
	defer func() { mgr.metrics.FQDNResolvers.Set(float64(len(mgr.resolvers))) }()

	newStatus := mgr.cache.deepCopy()
	newStatus[fqdnGroup] = fqdns

	newFQDNs, staleFQDNs := mgr.cache.diff(newStatus)

	// start a reconciler for each new fqdn to resolve
	mgr.logger.WithFields(logrus.Fields{
		"fqdnGroup":    fqdnGroup,
		"newResolvers": newFQDNs,
	}).Debug("starting new fqdn resolvers after FQDNGroup event")

	for _, fqdn := range newFQDNs {
		resolver := newResolver(mgr.logger, fqdn, fqdnGroup, mgr.dnsClient, mgr.minInterval, mgr.store)
		if err := resolver.start(); err != nil {
			return fmt.Errorf("failed to start resolver for %s: %w", fqdn, err)
		}
		mgr.resolvers[fqdn] = resolver
	}

	// stop any stale resolver
	if len(staleFQDNs) > 0 {
		mgr.logger.WithFields(logrus.Fields{
			"fqdnGroup":      fqdnGroup,
			"staleResolvers": staleFQDNs,
		}).Debug("stopping stale fqdn resolvers after FQDNGroup event")
	}

	for _, fqdn := range staleFQDNs {
		resolver, ok := mgr.resolvers[fqdn]
		if !ok {
			return fmt.Errorf("fqdn resolver for %s not found", fqdn)
		}
		if err := resolver.stop(); err != nil {
			return fmt.Errorf("failed to close resolver for %s: %w", fqdn, err)
		}
		delete(mgr.resolvers, fqdn)
	}

	return nil
}

func isovalentFQDNGroup(lc cell.Lifecycle, cs client.Clientset) (resource.Resource[*v1alpha1.IsovalentFQDNGroup], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*v1alpha1.IsovalentFQDNGroupList](cs.IsovalentV1alpha1().IsovalentFQDNGroups())
	return resource.New[*v1alpha1.IsovalentFQDNGroup](lc, lw, resource.WithMetric("IsovalentFQDNGroup")), nil
}

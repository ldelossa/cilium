//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bfd

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	bgpv2config "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	clientv1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// retry options used in reconcileWithRetry method.
	// With this config, reconcile can repeat max 10 times within ~8.5 minutes.
	backoff = wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      0,
	}

	// maxErrorLen is the maximum length of error message to be logged.
	maxErrorLen = 1024
)

type bfdReconcilerParams struct {
	cell.In

	Cfg    types.BFDConfig
	BGPCfg bgpv2config.Config

	Logger    logrus.FieldLogger
	JobGroup  job.Group
	Clientset k8sclient.Clientset

	CiliumNodeResource            resource.Resource[*ciliumv2.CiliumNode]
	BFDNodeConfigResource         resource.Resource[*isovalentv1alpha1.IsovalentBFDNodeConfig]
	BFDNodeConfigOverrideResource resource.Resource[*isovalentv1alpha1.IsovalentBFDNodeConfigOverride]
	BGPClusterConfigResource      resource.Resource[*isovalentv1alpha1.IsovalentBGPClusterConfig]
	BGPPeerConfigResource         resource.Resource[*isovalentv1alpha1.IsovalentBGPPeerConfig]
}

type bfdReconciler struct {
	bfdReconcilerParams

	bfdNodeConfigClient clientv1alpha1.IsovalentBFDNodeConfigInterface

	ciliumNodeStore            resource.Store[*ciliumv2.CiliumNode]
	bfdNodeConfigStore         resource.Store[*isovalentv1alpha1.IsovalentBFDNodeConfig]
	bfdNodeConfigOverrideStore resource.Store[*isovalentv1alpha1.IsovalentBFDNodeConfigOverride]
	bgpClusterConfigStore      resource.Store[*isovalentv1alpha1.IsovalentBGPClusterConfig]
	bgpPeerConfigStore         resource.Store[*isovalentv1alpha1.IsovalentBGPPeerConfig]

	reconcileCh chan struct{}
}

func registerBFDReconciler(p bfdReconcilerParams) {
	if !p.BGPCfg.Enabled || !p.Cfg.BFDEnabled {
		return // both BGP and BFD must be enabled
	}
	m := &bfdReconciler{
		bfdReconcilerParams: p,
		reconcileCh:         make(chan struct{}, 1),
		bfdNodeConfigClient: p.Clientset.IsovalentV1alpha1().IsovalentBFDNodeConfigs(),
	}

	// initialize jobs and register them with lifecycle
	m.initializeJobs()
}

// initializeJobs initializes jobs of the BFD reconciler.
func (r *bfdReconciler) initializeJobs() {
	r.JobGroup.Add(
		job.OneShot("bfd-reconciler-main", func(ctx context.Context, health cell.Health) error {
			err := r.initializeStores(ctx)
			if err != nil {
				return err
			}
			return r.run(ctx, health)
		}),
		job.OneShot("cilium-node-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range r.CiliumNodeResource.Events(ctx) {
				r.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
		job.OneShot("bfd-node-config-override-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range r.BFDNodeConfigOverrideResource.Events(ctx) {
				r.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
		job.OneShot("bgp-cluster-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range r.BGPClusterConfigResource.Events(ctx) {
				r.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
		job.OneShot("bgp-peer-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range r.BGPPeerConfigResource.Events(ctx) {
				r.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
	)
}

// initializeStores initializes all necessary k8s resource stores.
func (r *bfdReconciler) initializeStores(ctx context.Context) (err error) {
	r.ciliumNodeStore, err = r.CiliumNodeResource.Store(ctx)
	if err != nil {
		return
	}
	r.bfdNodeConfigStore, err = r.BFDNodeConfigResource.Store(ctx)
	if err != nil {
		return
	}
	r.bfdNodeConfigOverrideStore, err = r.BFDNodeConfigOverrideResource.Store(ctx)
	if err != nil {
		return
	}
	r.bgpClusterConfigStore, err = r.BGPClusterConfigResource.Store(ctx)
	if err != nil {
		return
	}
	r.bgpPeerConfigStore, err = r.BGPPeerConfigResource.Store(ctx)
	if err != nil {
		return
	}
	return nil
}

// triggerReconcile initiates level triggered reconciliation.
func (r *bfdReconciler) triggerReconcile() {
	select {
	case r.reconcileCh <- struct{}{}:
		r.Logger.Debug("BFD reconciliation triggered")
	default:
	}
}

// run runs the BFD reconciler.
func (r *bfdReconciler) run(ctx context.Context, health cell.Health) (err error) {

	// trigger first reconciliation
	r.triggerReconcile()

	r.Logger.Info("BFD reconciler started")

	for {
		select {
		case _, open := <-r.reconcileCh:
			if !open {
				return
			}
			err := r.reconcileWithRetry(ctx, health)
			if err != nil {
				r.Logger.WithError(err).Error("BFD reconciliation failed")
			} else {
				r.Logger.Debug("BFD reconciliation successful")
			}
		case <-ctx.Done():
			return
		}
	}
}

// reconcileWithRetry runs reconcile with exponential backoff retry on error.
func (r *bfdReconciler) reconcileWithRetry(ctx context.Context, health cell.Health) error {
	return wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		r.Logger.Debug("BFD reconciliation started")
		err := r.reconcileBGPClusterConfigs(ctx)

		if err != nil {
			// log error, continue retry
			r.Logger.WithError(trimError(err, maxErrorLen)).Warn("BFD reconciliation error")
			health.Degraded("BFD reconciliation error", err)
			return false, nil
		}
		// no error, stop retry
		health.OK("BFD reconciliation successful")
		return true, nil
	})
}

// trimError trims error message to maxLen.
func trimError(err error, maxLen int) error {
	if err == nil {
		return nil
	}
	if len(err.Error()) > maxLen {
		return fmt.Errorf("%s... ", err.Error()[:maxLen])
	}
	return err
}

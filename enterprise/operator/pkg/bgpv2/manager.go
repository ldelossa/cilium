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
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// retry options used in reconcileWithRetry method.
	// steps will repeat for ~8.5 minutes.
	bo = wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      0,
	}

	// maxErrorLen is the maximum length of error message to be logged.
	maxErrorLen = 1024
)

type BGPResourceMapper struct {
	logger    logrus.FieldLogger
	jobs      job.Group
	signal    *signaler.BGPCPSignaler
	clientSet client.Clientset

	// BGPv2 Resources
	clusterConfig      store.BGPCPResourceStore[*v1alpha1.IsovalentBGPClusterConfig]
	peerConfig         store.BGPCPResourceStore[*v1alpha1.IsovalentBGPPeerConfig]
	advertisements     store.BGPCPResourceStore[*v1alpha1.IsovalentBGPAdvertisement]
	nodeConfigOverride store.BGPCPResourceStore[*v1alpha1.IsovalentBGPNodeConfigOverride]

	// for BGP node config, we do not need to trigger reconciliation on changes. So,
	// we use store.Resource instead of store.BGPCPResourceStore.
	nodeConfigStore resource.Store[*v1alpha1.IsovalentBGPNodeConfig]

	// BGPv2 OSS resources
	ossClusterConfigStore      resource.Store[*v2alpha1.CiliumBGPClusterConfig]
	ossPeerConfigStore         resource.Store[*v2alpha1.CiliumBGPPeerConfig]
	ossAdvertStore             resource.Store[*v2alpha1.CiliumBGPAdvertisement]
	ossNodeConfigOverrideStore resource.Store[*v2alpha1.CiliumBGPNodeConfigOverride]

	// Cilium node resource
	ciliumNode store.BGPCPResourceStore[*cilium_v2.CiliumNode]
}

type BGPResourceManagerParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Jobs      job.Group
	Config    config.Config
	Signal    *signaler.BGPCPSignaler
	ClientSet client.Clientset

	// BGPv2 Resources
	ClusterConfig      store.BGPCPResourceStore[*v1alpha1.IsovalentBGPClusterConfig]
	PeerConfig         store.BGPCPResourceStore[*v1alpha1.IsovalentBGPPeerConfig]
	Advertisements     store.BGPCPResourceStore[*v1alpha1.IsovalentBGPAdvertisement]
	NodeConfigOverride store.BGPCPResourceStore[*v1alpha1.IsovalentBGPNodeConfigOverride]
	NodeConfig         resource.Resource[*v1alpha1.IsovalentBGPNodeConfig]

	// BGPv2 OSS Resources
	OSSClusterConfig      resource.Resource[*v2alpha1.CiliumBGPClusterConfig]
	OSSPeerConfig         resource.Resource[*v2alpha1.CiliumBGPPeerConfig]
	OSSAdvert             resource.Resource[*v2alpha1.CiliumBGPAdvertisement]
	OSSNodeConfigOverride resource.Resource[*v2alpha1.CiliumBGPNodeConfigOverride]

	// Cilium node resource
	CiliumNode store.BGPCPResourceStore[*cilium_v2.CiliumNode]
}

func RegisterBGPResourceMapper(in BGPResourceManagerParams) error {
	if !in.Config.Enabled {
		return nil
	}

	m := &BGPResourceMapper{
		logger:             in.Logger,
		jobs:               in.Jobs,
		signal:             in.Signal,
		clientSet:          in.ClientSet,
		clusterConfig:      in.ClusterConfig,
		peerConfig:         in.PeerConfig,
		advertisements:     in.Advertisements,
		nodeConfigOverride: in.NodeConfigOverride,
		ciliumNode:         in.CiliumNode,
	}

	in.Jobs.Add(
		job.OneShot("enterprise-bgpv2-operator-main", func(ctx context.Context, health cell.Health) (err error) {
			// initialize node config store
			m.nodeConfigStore, err = in.NodeConfig.Store(ctx)
			if err != nil {
				return err
			}

			// initialize oss stores
			m.ossClusterConfigStore, err = in.OSSClusterConfig.Store(ctx)
			if err != nil {
				return err
			}
			m.ossPeerConfigStore, err = in.OSSPeerConfig.Store(ctx)
			if err != nil {
				return err
			}
			m.ossAdvertStore, err = in.OSSAdvert.Store(ctx)
			if err != nil {
				return err
			}
			m.ossNodeConfigOverrideStore, err = in.OSSNodeConfigOverride.Store(ctx)
			if err != nil {
				return err
			}

			m.logger.Info("Enterprise BGPv2 control plane operator started")
			m.Run(ctx)
			return
		}),
	)

	return nil
}

func (m *BGPResourceMapper) Run(ctx context.Context) {
	// trigger initial reconcile
	m.signal.Event(struct{}{})

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Enterprise BGPv2 control plane operator stopped")
			return
		case <-m.signal.Sig:
			err := m.reconcileWithRetry(ctx)
			if err != nil {
				m.logger.WithError(err).Error("BGP reconciliation failed")
			} else {
				m.logger.Debug("BGP reconciliation successful")
			}
		}
	}
}

func (m *BGPResourceMapper) reconcileWithRetry(ctx context.Context) error {
	retryFn := func(ctx context.Context) (bool, error) {
		err := m.reconcile(ctx)
		if err != nil {
			// log error, continue retry
			m.logger.WithError(TrimError(err, maxErrorLen)).Warn("BGP reconciliation error")
			return false, nil
		}

		// no error, stop retry
		return true, nil
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

func (m *BGPResourceMapper) reconcile(ctx context.Context) error {
	err := m.reconcileMappings(ctx)
	if err != nil {
		return err
	}

	return m.reconcileClusterConfigs(ctx)
}

// TrimError trims error message to maxLen.
func TrimError(err error, maxLen int) error {
	if err == nil {
		return nil
	}

	if len(err.Error()) > maxLen {
		return fmt.Errorf("%s... ", err.Error()[:maxLen])
	}
	return err
}

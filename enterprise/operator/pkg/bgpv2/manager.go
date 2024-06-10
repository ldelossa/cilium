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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
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

	// BGPv2 OSS resources
	ossClusterConfigStore      resource.Store[*v2alpha1.CiliumBGPClusterConfig]
	ossPeerConfigStore         resource.Store[*v2alpha1.CiliumBGPPeerConfig]
	ossAdvertStore             resource.Store[*v2alpha1.CiliumBGPAdvertisement]
	ossNodeConfigOverrideStore resource.Store[*v2alpha1.CiliumBGPNodeConfigOverride]
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

	// BGPv2 OSS Resources
	OSSClusterConfig      resource.Resource[*v2alpha1.CiliumBGPClusterConfig]
	OSSPeerConfig         resource.Resource[*v2alpha1.CiliumBGPPeerConfig]
	OSSAdvert             resource.Resource[*v2alpha1.CiliumBGPAdvertisement]
	OSSNodeConfigOverride resource.Resource[*v2alpha1.CiliumBGPNodeConfigOverride]
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
	}

	in.Jobs.Add(
		job.OneShot("enterprise-bgpv2-operator-main", func(ctx context.Context, health cell.Health) (err error) {
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
			// Reconcile TODO
		}
	}
}

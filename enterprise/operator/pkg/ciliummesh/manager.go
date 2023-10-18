//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ciliummesh

import (
	"context"
	"runtime/pprof"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

type CiliumMeshManagerParams struct {
	cell.In

	Cfg Config

	Logger      logrus.FieldLogger
	LC          cell.Lifecycle
	JobRegistry job.Registry
	Scope       cell.Scope

	Clientset k8sClient.Clientset
}

// CiliumMeshManager is responsible for managing Cilium Mesh feature
type CiliumMeshManager struct {
	cfg       Config
	logger    logrus.FieldLogger
	clientSet k8sClient.Clientset
}

func newCiliumMeshManager(p CiliumMeshManagerParams) (*CiliumMeshManager, error) {
	p.Logger.Info("Cilium Mesh new manager")

	if !p.Cfg.Enabled {
		return nil, nil
	}

	jobGroup := p.JobRegistry.NewGroup(
		p.Scope,
		job.WithLogger(p.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "cilium-mesh")),
	)
	cmm := &CiliumMeshManager{
		cfg:       p.Cfg,
		logger:    p.Logger,
		clientSet: p.Clientset,
	}

	jobGroup.Add(
		job.OneShot("cilium-mesh main", func(ctx context.Context, _ cell.HealthReporter) error {
			cmm.Run(ctx)
			return nil
		}),
	)

	p.LC.Append(jobGroup)

	return cmm, nil
}

func (cmm *CiliumMeshManager) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmm.logger.Info("Initializing")
	defer cmm.logger.Info("Shutting down")

	StartCiliumMeshEndpointSliceCreator(ctx, cmm.clientSet)
}

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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

type CiliumMeshManagerParams struct {
	cell.In

	Cfg Config

	Logger   logrus.FieldLogger
	JobGroup job.Group

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

	cmm := &CiliumMeshManager{
		cfg:       p.Cfg,
		logger:    p.Logger,
		clientSet: p.Clientset,
	}

	p.JobGroup.Add(
		job.OneShot("cilium-mesh-main", func(ctx context.Context, _ cell.Health) error {
			cmm.Run(ctx)
			return nil
		}),
	)

	return cmm, nil
}

func (cmm *CiliumMeshManager) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmm.logger.Info("Initializing")
	defer cmm.logger.Info("Shutting down")

	StartCiliumMeshEndpointSliceCreator(ctx, cmm.clientSet)
}

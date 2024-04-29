//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/time"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

type jobParams struct {
	cell.In

	Logger   logrus.FieldLogger
	JobGroup job.Group

	Config       cecmcfg.Config
	ClusterMesh  *clustermesh.ClusterMesh
	ClusterIDMgr ClusterIDsManager
}

func registerJobs(params jobParams) {
	if params.ClusterMesh == nil {
		return
	}

	if params.Config.EnableClusterAwareAddressing {
		params.JobGroup.Add(job.OneShot(
			"clustermesh-cleanup-stale-maps",
			cleanupStalePerClusterMapsJobFn(params),
			job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}),
		))
	}
}

func cleanupStalePerClusterMapsJobFn(params jobParams) job.OneShotFunc {
	return func(ctx context.Context, health cell.Health) error {
		// We don't actually care that nodes are synchronized here, but we need
		// to know that all ClusterIDs for existing clusters have been reserved.
		if err := params.ClusterMesh.NodesSynced(ctx); err != nil {
			return err
		}

		params.Logger.Info("Cleaning up all stale per-cluster maps")
		if err := params.ClusterIDMgr.cleanupStalePerClusterMaps(); err != nil {
			return fmt.Errorf("failed to clean up stale per-cluster maps: %w", err)
		}

		return nil
	}
}

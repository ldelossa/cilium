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
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/time"
)

func Test_ClusterConfigSteps(t *testing.T) {
	steps := []struct {
		name                string
		clusterConfig       *v1alpha1.IsovalentBGPClusterConfig
		nodeConfigOverride  *v1alpha1.IsovalentBGPNodeConfigOverride
		nodes               []*cilium_v2.CiliumNode
		expectedNodeConfigs []*v1alpha1.IsovalentBGPNodeConfig
	}{
		{
			name:          "initial node setup",
			clusterConfig: nil,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedNodeConfigs: nil,
		},
		{
			name:          "initial cluster configuration",
			clusterConfig: isoClusterConfig,
			expectedNodeConfigs: []*v1alpha1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
			},
		},
		{
			name:          "add new node",
			clusterConfig: isoClusterConfig,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedNodeConfigs: []*v1alpha1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
			},
		},
		{
			name:          "add node config override",
			clusterConfig: isoClusterConfig,
			nodeConfigOverride: &v1alpha1.IsovalentBGPNodeConfigOverride{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-3",
				},
				Spec: v1alpha1.IsovalentBGPNodeConfigOverrideSpec{
					BGPInstances: []v1alpha1.IsovalentBGPNodeConfigInstanceOverride{
						{
							Name:          "instance-1",
							SRv6Responder: ptr.To[bool](true),
						},
					},
				},
			},
			nodes: []*cilium_v2.CiliumNode{},
			expectedNodeConfigs: []*v1alpha1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpecWithResponder()},
					},
				},
			},
		},
		{
			name:          "remove node labels",
			clusterConfig: isoClusterConfig,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
				},
			},
			expectedNodeConfigs: nil,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	f, watchersReady := newFixture(ctx, require.New(t))

	tlog := hivetest.Logger(t)
	f.hive.Start(tlog, ctx)
	defer f.hive.Stop(tlog, ctx)

	watchersReady()

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			req := require.New(t)

			// setup nodes
			for _, node := range step.nodes {
				upsertNode(req, ctx, f, node)
			}

			// upsert BGP cluster config
			upsertIsoBGPCC(req, ctx, f, step.clusterConfig)

			// upsert BGP node config override
			upsertIsoBGPNodeConfigOR(req, ctx, f, step.nodeConfigOverride)

			// validate node configs
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				runningIsoNodeConfigs, err := f.isoBGPNodeConfClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}
				assert.Equal(c, len(step.expectedNodeConfigs), len(runningIsoNodeConfigs.Items))

				for _, expectedNodeConfig := range step.expectedNodeConfigs {
					isoNodeConfig, err := f.isoBGPNodeConfClient.Get(ctx, expectedNodeConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, expectedNodeConfig.Spec, isoNodeConfig.Spec)
				}

			}, TestTimeout, 50*time.Millisecond)
		})
	}
}

func upsertNode(req *require.Assertions, ctx context.Context, f *fixture, node *cilium_v2.CiliumNode) {
	_, err := f.nodeClient.Get(ctx, node.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.nodeClient.Create(ctx, node, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.nodeClient.Update(ctx, node, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

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
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
)

func TestReconcileParamsUpgrader(t *testing.T) {
	var (
		up paramUpgrader
		cs client.Clientset
		jg job.Group
	)

	h := hive.New(
		job.Cell,
		cell.Provide(
			newReconcileParamsUpgrader,
			client.NewFakeClientset,
			k8s.CiliumBGPNodeConfigResource,
			k8s.IsovalentBGPNodeConfigResource,
			cell.NewSimpleHealth,
			func(r job.Registry, health cell.Health) job.Group {
				return r.NewGroup(health)
			},
			// enterprise bgp is enabled
			func() config.Config {
				return config.Config{
					Enabled: true,
				}
			},
		),
		cell.Invoke(func(u paramUpgrader, c client.Clientset, j job.Group) {
			up = u
			cs = c
			jg = j
		}),
	)

	err := h.Start(slog.Default(), context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		h.Stop(slog.Default(), context.Background())
	})

	// start jobs in the group
	jg.Start(context.Background())

	ceeNode, err := cs.IsovalentV1alpha1().IsovalentBGPNodeConfigs().Create(
		context.Background(),
		&v1alpha1.IsovalentBGPNodeConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node0",
			},
			Spec: v1alpha1.IsovalentBGPNodeSpec{
				BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{
					{
						Name: "instance0",
					},
				},
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	ossNode, err := cs.CiliumV2alpha1().CiliumBGPNodeConfigs().Create(
		context.Background(),
		&v2alpha1.CiliumBGPNodeConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node0",
			},
			Spec: v2alpha1.CiliumBGPNodeSpec{
				BGPInstances: []v2alpha1.CiliumBGPNodeInstance{
					{
						Name: ceeNode.Spec.BGPInstances[0].Name,
					},
				},
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	ossParams := reconcilerv2.ReconcileParams{
		BGPInstance: &instance.BGPInstance{
			Config: &ossNode.Spec.BGPInstances[0],
			Router: types.NewFakeRouter(),
			Metadata: map[string]any{
				"foo": "bar",
			},
		},
		DesiredConfig: &ossNode.Spec.BGPInstances[0],
		CiliumNode: &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node0",
			},
		},
	}

	var ceeParams EnterpriseReconcileParams
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ceeParams, err = up.upgrade(ossParams)
		if !assert.NoError(ct, err) {
			return
		}
	}, time.Second*3, time.Millisecond*100)

	require.True(t,
		// Pointer equality
		ceeParams.BGPInstance.Router == ossParams.BGPInstance.Router,
		"CEE router doesn't point to the same router instance as OSS",
	)

	// Ensure the change to the metadata in CEE is visible in OSS
	ceeParams.BGPInstance.Metadata["baz"] = "qux"
	require.Equal(t,
		ceeParams.BGPInstance.Metadata["foo"], ossParams.BGPInstance.Metadata["foo"],
		"CEE Metadata must be a shallow copy of OSS Metadata (mismatched value for \"foo\")",
	)
	require.Equal(t,
		ceeParams.BGPInstance.Metadata["baz"], ossParams.BGPInstance.Metadata["baz"],
		"CEE Metadata must be a shallow copy of OSS Metadata (mismatched value for \"baz\")",
	)

	require.True(t,
		// Pointer equality
		ceeParams.CiliumNode == ossParams.CiliumNode,
		"CEE CiliumNode doesn't point to the same router instance as OSS",
	)
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package srv6manager

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/pkg/features"
	"github.com/cilium/cilium/pkg/ipam"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

var Cell = cell.Module(
	"srv6-manager",
	"SRv6 DataPath Manager",

	// The Controller which is the entry point of the module
	cell.Provide(NewSRv6Manager),

	cell.ProvidePrivate(
		newDaemonPromiseProvider,
		newIsovalentVRFResource,
		newIsovalentSRv6EgressPolicyResource,
	),

	// Force instantiation of SRv6Manager and override DaemonConfig
	cell.Invoke(func(m *Manager, dc *option.DaemonConfig) {
		if m != nil {
			// Override DaemonConfig to enforce attaching BPF program to
			// native devices. This is required for SRv6 decapsulation
			// handling.
			dc.ForceDeviceRequired = true
		}
	}),

	features.FeatureWithConfigT[*option.DaemonConfig](features.Spec{
		ID:          "SRv6",
		Name:        "SRv6",
		Description: "Enable SRv6 support",
		Stage:       features.Beta,
	}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
		return conf.EnableSRv6, nil
	})),
)

// daemon is an interface which minimize the surface of Daemon
// and make it easy to mock out. It only covers a minimal usecase
// necessary for SRv6 Manager.
type daemon interface {
	GetIPv6Allocator() ipam.Allocator
}

// daemonPromiseProvider converts raw Daemon promise to daemon promise
func newDaemonPromiseProvider(g job.Group, dp promise.Promise[*cmd.Daemon], dc *option.DaemonConfig) promise.Promise[daemon] {
	if !dc.EnableSRv6 {
		return nil
	}

	r, p := promise.New[daemon]()

	g.Add(job.OneShot("srv6-daemon-promise-job", func(ctx context.Context, health cell.Health) error {
		d, err := dp.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to await for Daemon: %w", err)
		}
		r.Resolve(d)
		return nil
	}))

	return p
}

func newIsovalentVRFResource(lc cell.Lifecycle, dc *option.DaemonConfig, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*iso_v1alpha1.IsovalentVRF], error) {
	if !cs.IsEnabled() || !dc.EnableSRv6 {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*iso_v1alpha1.IsovalentVRFList](cs.IsovalentV1alpha1().IsovalentVRFs()),
		opts...,
	)
	return resource.New[*iso_v1alpha1.IsovalentVRF](lc, lw, resource.WithMetric("IsovalentVRFResource")), nil
}

func newIsovalentSRv6EgressPolicyResource(lc cell.Lifecycle, dc *option.DaemonConfig, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*iso_v1alpha1.IsovalentSRv6EgressPolicy], error) {
	if !cs.IsEnabled() || !dc.EnableSRv6 {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*iso_v1alpha1.IsovalentSRv6EgressPolicyList](cs.IsovalentV1alpha1().IsovalentSRv6EgressPolicies()),
		opts...,
	)
	return resource.New[*iso_v1alpha1.IsovalentSRv6EgressPolicy](lc, lw, resource.WithMetric("IsovalentSRv6EgressPolicyResource")), nil
}

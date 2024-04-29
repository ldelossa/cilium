//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package multicast

import (
	"github.com/cilium/hive/cell"

	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
)

var Cell = cell.Module(
	"multicast-manager",
	"Multicast manager subsystem",

	cell.Provide(newMulticastManager),
	cell.ProvidePrivate(
		newMulticastGroupResource,
		newMulticastNodeResource,
	),

	cell.Invoke(func(manager *MulticastManager) {}),
)

func newMulticastGroupResource(lc cell.Lifecycle, c client.Clientset, cfg maps_multicast.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastGroup] {
	if !cfg.MulticastEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentMulticastGroup](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentMulticastGroupList](
			c.IsovalentV1alpha1().IsovalentMulticastGroups(),
		), resource.WithMetric("IsovalentMulticastGroup"))
}

func newMulticastNodeResource(lc cell.Lifecycle, c client.Clientset, cfg maps_multicast.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastNode] {
	if !cfg.MulticastEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentMulticastNode](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentMulticastNodeList](
			c.IsovalentV1alpha1().IsovalentMulticastNodes(),
		), resource.WithMetric("IsovalentMulticastNode"))
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func IsovalentFQDNGroup(lc cell.Lifecycle, cs client.Clientset) (resource.Resource[*isovalent_api_v1alpha1.IsovalentFQDNGroup], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentFQDNGroupList](cs.IsovalentV1alpha1().IsovalentFQDNGroups())
	return resource.New[*isovalent_api_v1alpha1.IsovalentFQDNGroup](lc, lw, resource.WithMetric("IsovalentFQDNGroup")), nil
}

func IsovalentBGPClusterConfigResource(lc cell.Lifecycle, c client.Clientset, bgpConfig config.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentBGPClusterConfig] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBGPClusterConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBGPClusterConfigList](
			c.IsovalentV1alpha1().IsovalentBGPClusterConfigs(),
		), resource.WithMetric("IsovalentBGPClusterConfig"))
}

func IsovalentBGPPeerConfigResource(lc cell.Lifecycle, c client.Clientset, bgpConfig config.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentBGPPeerConfig] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBGPPeerConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBGPPeerConfigList](
			c.IsovalentV1alpha1().IsovalentBGPPeerConfigs(),
		), resource.WithMetric("IsovalentBGPPeerConfig"))
}

func IsovalentBGPAdvertisementResource(lc cell.Lifecycle, c client.Clientset, bgpConfig config.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentBGPAdvertisement] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBGPAdvertisement](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBGPAdvertisementList](
			c.IsovalentV1alpha1().IsovalentBGPAdvertisements(),
		), resource.WithMetric("IsovalentBGPAdvertisement"))
}

func IsovalentBGPNodeConfigResource(lc cell.Lifecycle, c client.Clientset, bgpConfig config.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentBGPNodeConfig] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBGPNodeConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBGPNodeConfigList](
			c.IsovalentV1alpha1().IsovalentBGPNodeConfigs(),
		), resource.WithMetric("IsovalentBGPNodeConfig"))
}

func IsovalentBGPNodeConfigOverrideResource(lc cell.Lifecycle, c client.Clientset, bgpConfig config.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentBGPNodeConfigOverride] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBGPNodeConfigOverride](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBGPNodeConfigOverrideList](
			c.IsovalentV1alpha1().IsovalentBGPNodeConfigOverrides(),
		), resource.WithMetric("IsovalentBGPNodeConfigOverride"))
}

func IsovalentBFDProfileResource(lc cell.Lifecycle, c client.Clientset, cfg types.BFDConfig) resource.Resource[*isovalent_api_v1alpha1.IsovalentBFDProfile] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBFDProfile](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBFDProfileList](
			c.IsovalentV1alpha1().IsovalentBFDProfiles(),
		), resource.WithMetric("IsovalentBFDProfile"))
}

func IsovalentBFDNodeConfigResource(lc cell.Lifecycle, c client.Clientset, cfg types.BFDConfig) resource.Resource[*isovalent_api_v1alpha1.IsovalentBFDNodeConfig] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBFDNodeConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigList](
			c.IsovalentV1alpha1().IsovalentBFDNodeConfigs(),
		), resource.WithMetric("IsovalentBFDNodeConfig"))
}

func IsovalentBFDNodeConfigOverrideResource(lc cell.Lifecycle, c client.Clientset, cfg types.BFDConfig) resource.Resource[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigOverride] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigOverride](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigOverrideList](
			c.IsovalentV1alpha1().IsovalentBFDNodeConfigOverrides(),
		), resource.WithMetric("IsovalentBFDNodeConfigOverride"))
}

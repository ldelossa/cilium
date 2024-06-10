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
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (m *BGPResourceMapper) reconcileClusterConfigs(ctx context.Context) error {
	clusterConfigs, err := m.clusterConfig.List()
	if err != nil {
		return err
	}

	for _, clusterConfig := range clusterConfigs {
		err = errors.Join(err, m.reconcileClusterConfig(ctx, clusterConfig))
	}
	return err
}

func (m *BGPResourceMapper) reconcileClusterConfig(ctx context.Context, config *v1alpha1.IsovalentBGPClusterConfig) error {
	// get nodes which match node selector for given cluster config
	matchingNodes, err := m.getMatchingNodes(config.Spec.NodeSelector, config.Name)
	if err != nil {
		return err
	}

	// update node configs for matched nodes
	for nodeRef := range matchingNodes {
		upsertErr := m.upsertNodeConfig(ctx, config, nodeRef)
		if upsertErr != nil {
			err = errors.Join(err, upsertErr)
		}
	}

	// delete node configs for this cluster that are not in the matching nodes
	dErr := m.deleteStaleNodeConfigs(ctx, matchingNodes, config.Name)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	return err
}

func (m *BGPResourceMapper) upsertNodeConfig(ctx context.Context, config *v1alpha1.IsovalentBGPClusterConfig, nodeName string) error {
	prev, exists, err := m.nodeConfigStore.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return err
	}

	// find node override instances for given node
	var overrideInstances []v1alpha1.IsovalentBGPNodeConfigInstanceOverride
	override, overrideExists, err := m.nodeConfigOverride.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return err
	}
	if overrideExists {
		overrideInstances = override.Spec.BGPInstances
	}

	// create new config
	nodeConfig := &v1alpha1.IsovalentBGPNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: nodeName,
			OwnerReferences: []meta_v1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentBGPNodeConfigOverrideKindDefinition,
					Name:       config.GetName(),
					UID:        config.GetUID(),
				},
			},
		},
		Spec: v1alpha1.IsovalentBGPNodeSpec{
			BGPInstances: toNodeBGPInstance(config.Spec.BGPInstances, overrideInstances),
		},
	}

	nodeConfigClient := m.clientSet.IsovalentV1alpha1().IsovalentBGPNodeConfigs()

	switch {
	case exists && prev.Spec.DeepEqual(&nodeConfig.Spec):
		return nil
	case exists:
		// reinitialize spec and status fields
		prev.Spec = nodeConfig.Spec
		_, err = nodeConfigClient.Update(ctx, prev, meta_v1.UpdateOptions{})
	default:
		_, err = nodeConfigClient.Create(ctx, nodeConfig, meta_v1.CreateOptions{})
	}

	m.logger.WithFields(logrus.Fields{
		"node config":    nodeConfig.Name,
		"cluster config": config.Name,
	}).Debug("Updating Isovalent BGP node config")

	return err
}

func toNodeBGPInstance(clusterBGPInstances []v1alpha1.IsovalentBGPInstance, overrideBGPInstances []v1alpha1.IsovalentBGPNodeConfigInstanceOverride) []v1alpha1.IsovalentBGPNodeInstance {
	var res []v1alpha1.IsovalentBGPNodeInstance

	for _, clusterBGPInstance := range clusterBGPInstances {
		nodeBGPInstance := v1alpha1.IsovalentBGPNodeInstance{
			Name:     clusterBGPInstance.Name,
			LocalASN: clusterBGPInstance.LocalASN,
		}

		// find BGPResourceManager global override for this instance
		var override v1alpha1.IsovalentBGPNodeConfigInstanceOverride
		for _, overrideBGPInstance := range overrideBGPInstances {
			if overrideBGPInstance.Name == clusterBGPInstance.Name {
				nodeBGPInstance.RouterID = overrideBGPInstance.RouterID
				nodeBGPInstance.LocalPort = overrideBGPInstance.LocalPort
				override = overrideBGPInstance
				break
			}
		}

		for _, bgpInstancePeer := range clusterBGPInstance.Peers {
			nodePeer := v1alpha1.IsovalentBGPNodePeer{
				Name:          bgpInstancePeer.Name,
				PeerAddress:   bgpInstancePeer.PeerAddress,
				PeerASN:       bgpInstancePeer.PeerASN,
				PeerConfigRef: bgpInstancePeer.PeerConfigRef,
			}

			// find BGPResourceManager Peer override for this instance
			for _, overrideBGPPeer := range override.Peers {
				if overrideBGPPeer.Name == bgpInstancePeer.Name {
					nodePeer.LocalAddress = overrideBGPPeer.LocalAddress
					break
				}
			}

			nodeBGPInstance.Peers = append(nodeBGPInstance.Peers, nodePeer)
		}

		res = append(res, nodeBGPInstance)
	}
	return res
}

// deleteStaleNodeConfigs deletes node configs that are not in the expected list for given cluster.
func (m *BGPResourceMapper) deleteStaleNodeConfigs(ctx context.Context, expectedNodes sets.Set[string], clusterRef string) (err error) {
	for _, existingNode := range m.nodeConfigStore.List() {
		if expectedNodes.Has(existingNode.Name) || !IsOwner(existingNode.GetOwnerReferences(), clusterRef) {
			continue
		}

		dErr := m.clientSet.IsovalentV1alpha1().IsovalentBGPNodeConfigs().Delete(ctx, existingNode.Name, meta_v1.DeleteOptions{})
		if dErr != nil && k8s_errors.IsNotFound(dErr) {
			continue
		} else if dErr != nil {
			err = errors.Join(err, dErr)
		} else {
			m.logger.WithFields(logrus.Fields{
				"node config":    existingNode.Name,
				"cluster config": clusterRef,
			}).Debug("Deleting Isovalent BGP node config")
		}
	}
	return err
}

// getMatchingNodes returns a map of node names that match the given cluster config's node selector.
func (m *BGPResourceMapper) getMatchingNodes(nodeSelector *slim_meta_v1.LabelSelector, configName string) (sets.Set[string], error) {
	labelSelector, err := slim_meta_v1.LabelSelectorAsSelector(nodeSelector)
	if err != nil {
		return nil, err
	}

	// find nodes that match the cluster config's node selector
	matchingNodes := sets.New[string]()

	ciliumNodes, err := m.ciliumNode.List()
	if err != nil {
		return nil, err
	}

	for _, n := range ciliumNodes {
		// nil node selector means match all nodes
		if nodeSelector == nil || labelSelector.Matches(slim_labels.Set(n.Labels)) {
			err := m.validNodeSelection(n, configName)
			if err != nil {
				m.logger.WithError(err).Errorf("skipping node %s", n.Name)
				continue
			}
			matchingNodes.Insert(n.Name)
		}
	}

	return matchingNodes, nil
}

// validNodeSelection checks if the node is already present in another cluster config.
func (m *BGPResourceMapper) validNodeSelection(node *cilium_v2.CiliumNode, expectedOwnerName string) error {
	existingBGPNodeConfig, exists, err := m.nodeConfigStore.GetByKey(resource.Key{Name: node.Name})
	if err != nil {
		return err
	}

	if exists && !IsOwner(existingBGPNodeConfig.GetOwnerReferences(), expectedOwnerName) {
		return fmt.Errorf("BGP node config %s already exist", existingBGPNodeConfig.Name)
	}

	return nil
}

// IsOwner checks if the expected is present in owners list.
func IsOwner(owners []meta_v1.OwnerReference, expected string) bool {
	for _, owner := range owners {
		if owner.Name == expected {
			return true
		}
	}
	return false
}

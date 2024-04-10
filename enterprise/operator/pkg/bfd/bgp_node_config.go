//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bfd

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// bfdPeerConfig represents desired config of a BFD peer.
type bfdPeerConfig struct {
	peerAddress string
	bfdProfile  string
}

// reconcileBGPClusterConfigs reconciles BFD configuration based on IsovalentBGPClusterConfig resources.
func (r *bfdReconciler) reconcileBGPClusterConfigs(ctx context.Context) error {
	var err error

	// Reconcile each existing IsovalentBGPClusterConfig.
	// Note that we do not need to care about deleted IsovalentBGPClusterConfig resources,
	// their child BFDNodeConfig resources are deleted automatically by k8s garbage collection
	// thanks to OwnerReferences.
	for _, cc := range r.bgpClusterConfigStore.List() {
		rcErr := r.reconcileBGPClusterConfig(ctx, cc)
		if rcErr != nil {
			err = errors.Join(err, rcErr)
		}
	}
	return err
}

// reconcileBGPClusterConfig reconciles BFD configuration based on the provided IsovalentBGPClusterConfig resource.
func (r *bfdReconciler) reconcileBGPClusterConfig(ctx context.Context, bgpCC *isovalentv1alpha1.IsovalentBGPClusterConfig) error {
	// get all desired BFD peers configured in the BGPClusterConfig
	bfdPeers, err := r.getDesiredBFDPeers(bgpCC)
	if err != nil {
		return err
	}

	// get nodes which match the node selector of the given BGPClusterConfig
	matchingNodes, err := r.getMatchingNodes(bgpCC.Spec.NodeSelector)
	if err != nil {
		return err
	}

	// reconcile BFD node config for each matching node
	for _, node := range matchingNodes {
		reconcileErr := r.reconcileBFDNodeConfig(ctx, bgpCC, node, bfdPeers)
		if reconcileErr != nil {
			err = errors.Join(err, reconcileErr)
		}
	}

	// delete stale BFD node configs for the non-matching nodes
	dErr := r.deleteStaleBFDNodeConfigs(ctx, matchingNodes, bgpCC.Name)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	return err
}

// getDesiredBFDPeers returns a list of desired BFD peers configured in the provided IsovalentBGPClusterConfig.
func (r *bfdReconciler) getDesiredBFDPeers(bgpCC *isovalentv1alpha1.IsovalentBGPClusterConfig) ([]*bfdPeerConfig, error) {
	peersMap := make(map[string]*bfdPeerConfig)

	for _, instance := range bgpCC.Spec.BGPInstances {
		for _, p := range instance.Peers {
			if p.PeerAddress == nil || p.PeerConfigRef == nil {
				continue
			}
			peerConfig, exists, err := r.bgpPeerConfigStore.GetByKey(resource.Key{Name: p.PeerConfigRef.Name})
			if err != nil {
				return nil, err
			}
			if !exists {
				continue
			}
			if peerConfig.Spec.BFDProfileRef != nil {
				if existing, exists := peersMap[*p.PeerAddress]; exists {
					// BFD peer with this address already exists for this BGPClusterConfig, skip
					if existing.bfdProfile != *peerConfig.Spec.BFDProfileRef {
						r.Logger.WithFields(logrus.Fields{
							BGPClusterConfigField: bgpCC.Name,
							PeerAddressField:      *p.PeerAddress,
						}).Warnf("Same BFD peer configured with different BFD profiles, '%s' will be used", existing.bfdProfile)
					}
					continue
				}
				peersMap[*p.PeerAddress] = &bfdPeerConfig{
					peerAddress: *p.PeerAddress,
					bfdProfile:  *peerConfig.Spec.BFDProfileRef,
				}
			}
		}
	}

	// sort peers to generate deterministic order
	peers := maps.Values(peersMap)
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].peerAddress < peers[j].peerAddress
	})
	return peers, nil
}

// getMatchingNodes returns a map of node names that match the given node selector.
func (r *bfdReconciler) getMatchingNodes(nodeSelector *slim_meta_v1.LabelSelector) ([]*ciliumv2.CiliumNode, error) {
	labelSelector, err := slim_meta_v1.LabelSelectorAsSelector(nodeSelector)
	if err != nil {
		return nil, err
	}

	// find nodes that match the node selector
	var nodes []*ciliumv2.CiliumNode

	for _, n := range r.ciliumNodeStore.List() {
		// nil node selector matches all nodes
		if nodeSelector == nil || labelSelector.Matches(slim_labels.Set(n.Labels)) {
			nodes = append(nodes, n)
		}
	}
	return nodes, nil
}

// reconcileBFDNodeConfig reconciles node config for the given IsovalentBGPClusterConfig and node.
func (r *bfdReconciler) reconcileBFDNodeConfig(ctx context.Context, bgpCC *isovalentv1alpha1.IsovalentBGPClusterConfig, node *ciliumv2.CiliumNode, peers []*bfdPeerConfig) error {
	// find node override config for the given node
	overrideConfig := make(map[string]*isovalentv1alpha1.BFDNodeConfigOverridePeer)
	override, overrideExists, err := r.bfdNodeConfigOverrideStore.GetByKey(resource.Key{Name: node.Name})
	if err != nil {
		return err
	}
	if overrideExists {
		for _, p := range override.Spec.Peers {
			overrideConfig[p.PeerAddress] = p
		}
	}

	// construct desired node config
	desired := &isovalentv1alpha1.IsovalentBFDNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: getNodeConfigName(bgpCC.Name, node.Name),
			OwnerReferences: []meta_v1.OwnerReference{
				{
					APIVersion: isovalentv1alpha1.SchemeGroupVersion.String(),
					Kind:       isovalentv1alpha1.IsovalentBGPClusterConfigKindDefinition,
					Name:       bgpCC.GetName(),
					UID:        bgpCC.GetUID(),
				},
			},
		},
		Spec: isovalentv1alpha1.BFDNodeConfigSpec{
			NodeRef: node.Name,
		},
	}
	for _, peer := range peers {
		peerConfig := &isovalentv1alpha1.BFDNodePeerConfig{
			Name:          getBFDPeerName(peer.peerAddress),
			PeerAddress:   peer.peerAddress,
			BFDProfileRef: peer.bfdProfile,
		}
		if o, exist := overrideConfig[peer.peerAddress]; exist {
			peerConfig.Interface = o.Interface
			peerConfig.LocalAddress = o.LocalAddress
			peerConfig.EchoSourceAddress = o.EchoSourceAddress
		}
		desired.Spec.Peers = append(desired.Spec.Peers, peerConfig)
	}

	// retrieve existing node config with the same name
	existing, exists, err := r.bfdNodeConfigStore.GetByKey(resource.Key{Name: desired.Name})
	if err != nil {
		return fmt.Errorf("failed to retrieve BFD node config: %w", err)
	}

	logger := r.Logger.WithFields(logrus.Fields{
		BGPClusterConfigField: bgpCC.Name,
		NodeConfigNameField:   desired.Name,
		NodeNameField:         node.Name,
	})

	switch {
	case exists && existing.Spec.DeepEqual(&desired.Spec):
		// existing spec equals the desired - no change needed
		return nil
	case exists && len(peers) == 0:
		// no desired peers - delete the existing resource
		logger.Debug("Deleting BFD node config")
		err = r.bfdNodeConfigClient.Delete(ctx, existing.Name, meta_v1.DeleteOptions{})
		if err != nil && !k8s_errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete BFD node config: %w", err)
		}
	case exists && len(peers) > 0:
		// update the spec
		logger.Debug("Updating BFD node config")
		existing.Spec = desired.Spec
		_, err = r.bfdNodeConfigClient.Update(ctx, existing, meta_v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update BFD node config: %w", err)
		}
	case !exists && len(peers) > 0:
		// create the resource
		logger.Debug("Creating BFD node config")
		_, err = r.bfdNodeConfigClient.Create(ctx, desired, meta_v1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create BFD node config: %w", err)
		}
	}
	return nil
}

// deleteStaleBFDNodeConfigs deletes stale BFD node configs for nodes that are not in the expected nodes list.
func (r *bfdReconciler) deleteStaleBFDNodeConfigs(ctx context.Context, expectedNodes []*ciliumv2.CiliumNode, bgpCCName string) error {
	nodeConfigList, err := r.bfdNodeConfigClient.List(ctx, meta_v1.ListOptions{})
	if err != nil {
		return err
	}

	expectedNodesSet := sets.New[string]()
	for _, n := range expectedNodes {
		expectedNodesSet.Insert(n.Name)
	}

	for _, nodeConfig := range nodeConfigList.Items {
		if expectedNodesSet.Has(nodeConfig.Spec.NodeRef) || !isOwner(nodeConfig.GetOwnerReferences(), bgpCCName) {
			continue // expected node or not managed by us, skip
		}
		r.Logger.WithFields(logrus.Fields{
			BGPClusterConfigField: bgpCCName,
			NodeConfigNameField:   nodeConfig.Name,
			NodeNameField:         nodeConfig.Name,
		}).Debug("Deleting stale BFD nodeConfig config")

		dErr := r.bfdNodeConfigClient.Delete(ctx, nodeConfig.Name, meta_v1.DeleteOptions{})
		if dErr != nil && k8s_errors.IsNotFound(dErr) {
			continue // already deleted
		} else if dErr != nil {
			err = errors.Join(err, dErr)
		}
	}
	return err
}

// getNodeConfigName returns IsovalentBFDNodeConfig resource name for given IsovalentBGPClusterConfig name and node name.
func getNodeConfigName(bgpCCName, nodeName string) string {
	return "bgp-" + bgpCCName + "-" + nodeName
}

// getBFDPeerName returns a logical name for a BFD peer with the given address.
func getBFDPeerName(address string) string {
	return "peer-" + address
}

// IsOwner checks if the ownerName is present in the owners list.
func isOwner(owners []meta_v1.OwnerReference, ownerName string) bool {
	for _, owner := range owners {
		if owner.Name == ownerName {
			return true
		}
	}
	return false
}

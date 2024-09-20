//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/maps"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

const (
	maxTTLValue = 255
)

type bfdReconcilerParams struct {
	cell.In

	Logger         logrus.FieldLogger
	JobGroup       job.Group
	Cfg            types.BFDConfig
	LocalNodeStore *node.LocalNodeStore
	Sysctl         sysctl.Sysctl

	DB            *statedb.DB
	BFDPeersTable statedb.RWTable[*types.BFDPeerStatus]

	BFDProfileResource    resource.Resource[*v1alpha1.IsovalentBFDProfile]
	BFDNodeConfigResource resource.Resource[*v1alpha1.IsovalentBFDNodeConfig]

	BFDServer types.BFDServer
}

type bfdReconciler struct {
	bfdReconcilerParams

	bfdProfileStore    resource.Store[*v1alpha1.IsovalentBFDProfile]
	bfdNodeConfigStore resource.Store[*v1alpha1.IsovalentBFDNodeConfig]

	bfdProfileSyncCh    chan struct{}
	bfdNodeConfigSyncCh chan struct{}
	reconcileCh         chan struct{}

	nodeName string

	configuredPeers map[string]*peerConfig // configured peers keyed by nodeConfigName + peerName
}

// peerConfig represents desired configuration of a BFD peer, with reference to its configuration source.
type peerConfig struct {
	nodeConfigName string
	peerName       string
	config         *types.BFDPeerConfig
}

// key is the unique key of a BFD peer config.
func (p *peerConfig) key() string {
	return p.nodeConfigName + "-" + p.peerName
}

// logFields returns log fields populated with the peerConfig configuration.
func (p *peerConfig) logFields() logrus.Fields {
	return logrus.Fields{
		types.PeerNameField:       p.peerName,
		types.NodeConfigNameField: p.nodeConfigName,
		types.PeerAddressField:    p.config.PeerAddress,
	}
}

func newBFDReconciler(p bfdReconcilerParams) *bfdReconciler {
	if !p.Cfg.BFDEnabled {
		return nil
	}
	r := &bfdReconciler{
		bfdReconcilerParams: p,
		bfdProfileSyncCh:    make(chan struct{}, 1),
		bfdNodeConfigSyncCh: make(chan struct{}, 1),
		reconcileCh:         make(chan struct{}, 1),
		configuredPeers:     make(map[string]*peerConfig),
	}

	// initialize jobs and register them within lifecycle
	r.initializeJobs()

	p.Logger.Info("BFD Reconciler initialized")
	return r
}

func (r *bfdReconciler) initializeJobs() {
	r.JobGroup.Add(
		job.OneShot("bfd-main", func(ctx context.Context, health cell.Health) (err error) {
			r.bfdProfileStore, err = r.BFDProfileResource.Store(ctx)
			if err != nil {
				return
			}

			r.bfdNodeConfigStore, err = r.BFDNodeConfigResource.Store(ctx)
			if err != nil {
				return
			}

			localNode, err := r.LocalNodeStore.Get(ctx)
			if err != nil {
				return err
			}
			r.nodeName = localNode.Name

			r.triggerReconcile()
			r.run(ctx)
			return nil
		}),

		job.OneShot("bfd-server", func(ctx context.Context, health cell.Health) (err error) {
			r.BFDServer.Run(ctx)
			return nil
		}),

		job.OneShot("bfd-profile-observer", func(ctx context.Context, health cell.Health) error {
			for e := range r.BFDProfileResource.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case r.bfdProfileSyncCh <- struct{}{}:
					default:
					}
				}
				r.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bfd-node-config-observer", func(ctx context.Context, health cell.Health) error {
			for e := range r.BFDNodeConfigResource.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case r.bfdNodeConfigSyncCh <- struct{}{}:
					default:
					}
				}
				r.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bfd-peer-status-observer", func(ctx context.Context, health cell.Health) error {
			for e := range stream.ToChannel[types.BFDPeerStatus](ctx, r.BFDServer) {
				r.handlePeerStatusUpdate(&e)
			}
			return nil
		}),
	)
}

func (r *bfdReconciler) run(ctx context.Context) {
	r.Logger.Info("Starting BFD reconciler")
	defer r.Logger.Info("Stopping BFD reconciler")

	// wait for resources to sync
	<-r.bfdProfileSyncCh
	<-r.bfdNodeConfigSyncCh

	r.Logger.Info("Initial sync of BFD resources completed")

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.reconcileCh:
			err := r.reconcile(ctx)
			if err != nil {
				r.Logger.WithError(err).Error("Failed to reconcile BFD config")
			}
		}
	}
}

func (r *bfdReconciler) triggerReconcile() {
	select {
	case r.reconcileCh <- struct{}{}:
	default:
	}
}

func (r *bfdReconciler) reconcile(ctx context.Context) error {
	r.Logger.Debug("Starting BFD reconciliation")

	// reconcileErr will contain all reconciliation errors.
	// Reconciliation is best-effort: if a BFD peer can not be reconciled, it continues with other peers.
	var reconcileErr error

	// compile desired BFD peers
	desired := make(map[string]*peerConfig)

	for _, nc := range r.bfdNodeConfigStore.List() {
		if nc.Spec.NodeRef == r.nodeName {
			for _, peer := range nc.Spec.Peers {
				profile, exists, err := r.bfdProfileStore.GetByKey(resource.Key{Name: peer.BFDProfileRef})
				if err != nil {
					r.Logger.WithError(err).WithField(types.ProfileNameField, peer.BFDProfileRef).
						Error("Failed to retrieve BFD profile, skipping peer reconciliation")
					reconcileErr = errors.Join(reconcileErr, err)
					continue
				}
				if !exists {
					continue // may not be configured yet, nothing to do
				}
				cfg, err := r.getDesiredBFDPeerConfig(peer, profile)
				if err != nil {
					r.Logger.WithError(err).WithField(types.PeerNameField, peer.Name).
						Error("Failed to generate desired BFD peer config, skipping peer reconciliation")
					reconcileErr = errors.Join(reconcileErr, err)
					continue
				}
				peerCfg := &peerConfig{
					nodeConfigName: nc.Name,
					peerName:       peer.Name,
					config:         cfg,
				}
				desired[peerCfg.key()] = peerCfg
			}
		}
	}

	// compile the list of peers to add / update/ delete
	var toAdd, toUpdate, toDelete []*peerConfig

	// use sorted desired / configured values to reconcile deterministically
	for _, val := range r.sortedPeerConfigValues(desired) {
		if existing, exists := r.configuredPeers[val.key()]; !exists {
			toAdd = append(toAdd, val)
		} else if *existing.config != *val.config {
			toUpdate = append(toUpdate, val)
		}
	}
	for _, val := range r.sortedPeerConfigValues(r.configuredPeers) {
		if _, exists := desired[val.key()]; !exists {
			toDelete = append(toDelete, val)
		}
	}

	// Add / Update / Delete peers and populate last configured state.
	// Reconcile with the best effort - upon error (e.g. due to potential conflicts between multiple peers),
	// log an error and continue reconciling other peers.

	for _, peer := range toAdd {
		err := r.addPeer(peer)
		if err != nil {
			r.Logger.WithError(err).WithFields(peer.logFields()).
				Error("Failed to add BFD peer, BFD peer configuration may be inconsistent")
			reconcileErr = errors.Join(reconcileErr, err)
		} else {
			r.configuredPeers[peer.key()] = peer
		}
	}
	for _, peer := range toUpdate {
		err := r.updatePeer(peer)
		if err != nil {
			r.Logger.WithError(err).WithFields(peer.logFields()).
				Error("Failed to update BFD peer, BFD peer configuration may be inconsistent")
			reconcileErr = errors.Join(reconcileErr, err)
		} else {
			r.configuredPeers[peer.key()] = peer
		}
	}
	for _, peer := range toDelete {
		err := r.deletePeer(peer)
		if err != nil {
			r.Logger.WithError(err).WithFields(peer.logFields()).
				Error("Failed to delete BFD peer, BFD peer configuration may be inconsistent")
			reconcileErr = errors.Join(reconcileErr, err)
		} else {
			delete(r.configuredPeers, peer.key())
		}
	}
	return reconcileErr
}

// getDesiredBFDPeerConfig generates BFD peer configuration from high-level BFD peer config and BFD profile
func (r *bfdReconciler) getDesiredBFDPeerConfig(peer *v1alpha1.BFDNodePeerConfig, profile *v1alpha1.IsovalentBFDProfile) (*types.BFDPeerConfig, error) {
	peerAddr, err := netip.ParseAddr(peer.PeerAddress)
	if err != nil {
		return nil, fmt.Errorf("error parsing BFD peer address '%s': %w", peer.PeerAddress, err)
	}

	localAddr := netip.Addr{}
	if peer.LocalAddress != nil {
		localAddr, err = netip.ParseAddr(*peer.LocalAddress)
		if err != nil {
			return nil, fmt.Errorf("error parsing BFD peer local address '%s': %w", *peer.LocalAddress, err)
		}
	}

	cfg := &types.BFDPeerConfig{
		PeerAddress:      peerAddr,
		LocalAddress:     localAddr,
		DetectMultiplier: uint8(pointer.Int32Deref(profile.Spec.DetectMultiplier, 0)),
		TransmitInterval: time.Duration(pointer.Int32Deref(profile.Spec.TransmitIntervalMilliseconds, 0)) * time.Millisecond,
		ReceiveInterval:  time.Duration(pointer.Int32Deref(profile.Spec.ReceiveIntervalMilliseconds, 0)) * time.Millisecond,
	}
	if peer.Interface != nil {
		cfg.Interface = *peer.Interface
	}
	if profile.Spec.MinimumTTL != nil {
		cfg.MinimumTTL = uint8(*profile.Spec.MinimumTTL)
		if cfg.MinimumTTL < maxTTLValue {
			cfg.Multihop = true
		}
	}
	if profile.Spec.EchoFunction != nil {
		if slices.Contains(profile.Spec.EchoFunction.Directions, v1alpha1.BFDEchoFunctionDirectionReceive) {
			cfg.EchoReceiveInterval =
				time.Duration(pointer.Int32Deref(profile.Spec.EchoFunction.ReceiveIntervalMilliseconds, 0)) * time.Millisecond
		}
		if slices.Contains(profile.Spec.EchoFunction.Directions, v1alpha1.BFDEchoFunctionDirectionTransmit) {
			cfg.EchoTransmitInterval =
				time.Duration(pointer.Int32Deref(profile.Spec.EchoFunction.TransmitIntervalMilliseconds, 0)) * time.Millisecond

			if peer.EchoSourceAddress != nil && *peer.EchoSourceAddress != "" {
				cfg.EchoSourceAddress, err = netip.ParseAddr(*peer.EchoSourceAddress)
				if err != nil {
					return nil, fmt.Errorf("error parsing BFD echo source address '%s': %w", *peer.EchoSourceAddress, err)
				}
			}
		}
	}

	// Auto-detect interface for non-multihop peers.
	// NOTE: We do this auto-detection in the reconciler, as in case that the routing changes, the peering
	// needs to be re-created. However, we do not actively detect and trigger reconcile upon such events.
	if !cfg.Multihop && cfg.Interface == "" {
		if cfg.PeerAddress.Is6() && cfg.PeerAddress.IsLinkLocalUnicast() {
			return nil, errors.New("interface must be specified for peers with link-local IPv6 address")
		}
		cfg.Interface, err = detectEgressInterface(cfg.LocalAddress, cfg.PeerAddress)
		if err != nil {
			return nil, fmt.Errorf("could not auto-detect egress interface for peer %v: %w", cfg.PeerAddress, err)
		}
		r.Logger.WithFields(logrus.Fields{
			types.PeerAddressField:   peer.PeerAddress,
			types.InterfaceNameField: cfg.Interface,
		}).Debug("Auto-detected egress interface for the peer")
	}
	return cfg, nil
}

// sortedPeerConfigValues returns a sorted slice with peerConfig values from a map.
func (r *bfdReconciler) sortedPeerConfigValues(cfgMap map[string]*peerConfig) []*peerConfig {
	values := maps.Values(cfgMap)
	sort.Slice(values, func(i, j int) bool {
		if values[i].nodeConfigName != values[j].nodeConfigName {
			return values[i].nodeConfigName < values[j].nodeConfigName
		}
		return values[i].peerName < values[j].peerName
	})
	return values
}

// addPeer adds a new BFD peer on the BFD server.
// Also creates its entry in statedb, so that can be updated in handlePeerStatusUpdate.
func (r *bfdReconciler) addPeer(peer *peerConfig) error {
	logger := r.Logger.WithFields(peer.logFields())
	logger.Debug("Adding BFD peer")

	// create a statedb entry first, to not miss the first event
	err, dbObjCreated := r.createPeerStateDBObj(peer.config)
	if err != nil {
		return fmt.Errorf("error creating BFD peer in statedb: %w", err)
	}

	err = r.ensureEchoInterfaceSysctlConfig(peer.config)
	if err != nil {
		return fmt.Errorf("error ensuring sysctl config: %w", err)
	}

	// add the BFD peer on the BFD server
	err = r.BFDServer.AddPeer(peer.config)
	if err != nil {
		if dbObjCreated {
			// cleanup just created statedb entry
			delErr := r.deletePeerStateDBObj(peer.config)
			if delErr != nil {
				logger.WithError(delErr).Warn("Failed deleting statedb entry for the peer, stale entry may be left in it.")
			}
		}
		return fmt.Errorf("error creating BFD peer: %w", err)
	}
	return nil
}

// updatePeer updates a BFD peer on the BFD server.
func (r *bfdReconciler) updatePeer(peer *peerConfig) error {
	logger := r.Logger.WithFields(peer.logFields())
	desired := peer.config
	existing := r.configuredPeers[peer.key()].config

	err := r.ensureEchoInterfaceSysctlConfig(peer.config)
	if err != nil {
		return fmt.Errorf("error ensuring sysctl config: %w", err)
	}

	if desired.PeerAddress != existing.PeerAddress || desired.Interface != existing.Interface ||
		desired.LocalAddress != existing.LocalAddress ||
		(desired.EchoTransmitInterval == 0) != (existing.EchoTransmitInterval == 0) ||
		desired.EchoSourceAddress != existing.EchoSourceAddress ||
		desired.Multihop != existing.Multihop || desired.MinimumTTL != existing.MinimumTTL {

		// connection-related config change, we need to re-create the peer
		logger.Debug("Re-creating BFD peer")
		err := r.BFDServer.DeletePeer(existing)
		if err != nil {
			return fmt.Errorf("error deleting BFD peer: %w", err)
		}
		err = r.BFDServer.AddPeer(desired)
		if err != nil {
			return fmt.Errorf("error creating BFD peer: %w", err)
		}
		return nil
	}

	// detection interval -related change, we can update existing peer
	logger.Debug("Updating BFD peer")
	err = r.BFDServer.UpdatePeer(desired)
	if err != nil {
		return fmt.Errorf("error updating BFD peer: %w", err)
	}

	// note that there is no need to update peer in the statedb here,
	// it will be updated via status update(s) from the BFD server.
	return nil
}

// deletePeer deletes a BFD peer from the BFD server.
// Also removes its entry from statedb, so that handlePeerStatusUpdate can not update it anymore.
func (r *bfdReconciler) deletePeer(peer *peerConfig) error {
	r.Logger.WithFields(peer.logFields()).Debug("Deleting BFD peer")

	err := r.BFDServer.DeletePeer(peer.config)
	if err != nil {
		return fmt.Errorf("error deleting BFD peer: %w", err)
	}

	err = r.deletePeerStateDBObj(peer.config)
	if err != nil {
		return fmt.Errorf("error deleting BFD object from statedb: %w", err)
	}
	return nil
}

// createPeerStateDBObj creates BFD peer's entry in the statedb table, if it does not already exist.
// If the entry for the peer already existed, created returns false.
func (r *bfdReconciler) createPeerStateDBObj(cfg *types.BFDPeerConfig) (err error, created bool) {
	txn := r.DB.WriteTxn(r.BFDPeersTable)
	peer := &types.BFDPeerStatus{
		PeerAddress: cfg.PeerAddress,
		Interface:   cfg.Interface,
		// Set the initial state to AdminDown.
		// Once the session is configured on the BFD server, it will automatically transition to Down.
		Local: types.BFDSessionStatus{
			State: types.BFDStateAdminDown,
		},
	}
	_, hadOld, err := r.BFDPeersTable.Insert(txn, peer)
	if err != nil {
		txn.Abort()
		return err, false
	}
	if hadOld {
		txn.Abort()
		return nil, false
	}
	txn.Commit()
	return nil, true
}

// deletePeerStateDBObj deletes BFD peer's entry from the statedb table.
func (r *bfdReconciler) deletePeerStateDBObj(cfg *types.BFDPeerConfig) error {
	txn := r.DB.WriteTxn(r.BFDPeersTable)
	peer := &types.BFDPeerStatus{
		PeerAddress: cfg.PeerAddress,
		Interface:   cfg.Interface,
	}
	_, _, err := r.BFDPeersTable.Delete(txn, peer)
	if err != nil {
		txn.Abort()
		return err
	}
	txn.Commit()
	return nil
}

// handlePeerStatusUpdate handles BFD peer status updates coming from the BFD server.
func (r *bfdReconciler) handlePeerStatusUpdate(peer *types.BFDPeerStatus) {
	logger := r.Logger.WithFields(logrus.Fields{
		types.PeerAddressField:   peer.PeerAddress,
		types.DiscriminatorField: peer.Local.Discriminator,
		types.SessionStateField:  peer.Local.State,
	})
	logger.Debug("BFD status update")

	// Update the peer status in statedb, but only if its statedb entry exists,
	// to not produce stale entries for sessions that were deleted in the meantime.
	txn := r.DB.WriteTxn(r.BFDPeersTable)
	_, exists, err := r.BFDPeersTable.Insert(txn, peer)
	if err != nil {
		logger.WithError(err).Error("Error updating BFD peer's statedb entry, statedb state may be outdated")
		txn.Abort()
		return
	}
	if !exists {
		txn.Abort() // the peer may have been already deleted
		return
	}
	txn.Commit()
}

// ensureEchoInterfaceSysctlConfig ensures necessary sysctl config on the interface used for the provided BFD peer
// config if Echo function is enabled.
// NOTE: As multiple peers may be using the same interface, and other Cilium features may need to set the
// same sysctl parameters, we are not reverting this config when a BFD peer is being removed.
func (r *bfdReconciler) ensureEchoInterfaceSysctlConfig(cfg *types.BFDPeerConfig) error {
	if cfg.Interface != "" {
		if cfg.EchoTransmitInterval > 0 && cfg.PeerAddress.Is4() {
			// accept incoming packets with local source addresses (our echo packets)
			err := r.Sysctl.Enable([]string{"net", "ipv4", "conf", cfg.Interface, "accept_local"})
			if err != nil {
				return fmt.Errorf("error applying sysctl config: %w", err)
			}
			// do not test source IP against FIB
			err = r.Sysctl.Disable([]string{"net", "ipv4", "conf", cfg.Interface, "rp_filter"})
			if err != nil {
				return fmt.Errorf("error applying sysctl config: %w", err)
			}
		}
		if cfg.EchoReceiveInterval > 0 && cfg.PeerAddress.Is4() {
			// to not send ICMP redirects for the incoming echo packets generated by the peer
			// (if their source IP is from the interface's local subnet)
			err := r.Sysctl.Disable([]string{"net", "ipv4", "conf", cfg.Interface, "send_redirects"})
			if err != nil {
				return fmt.Errorf("error applying sysctl config: %w", err)
			}
		}
	}
	return nil
}

// detectEgressInterface detects egress interface based on a local IP address or a destination IP address.
func detectEgressInterface(localAddr, remoteAddr netip.Addr) (string, error) {
	var err error
	linkIndex := -1

	// if local address is specified, find interface with that IP
	if localAddr.IsValid() {
		linkIndex, err = getLinkByLocalAddr(localAddr)
		if err != nil {
			return "", fmt.Errorf("error by interface lookup by local address: %w", err)
		}
	}
	// otherwise lookup remote address in the routing table
	if linkIndex == -1 {
		linkIndex, err = getLinkByRemoteAddr(remoteAddr)
		if err != nil {
			return "", fmt.Errorf("error by interface lookup by remote address: %w", err)
		}
	}
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return "", fmt.Errorf("error by retrieving link by index (%d): %w", linkIndex, err)
	}
	return link.Attrs().Name, nil
}

func getLinkByLocalAddr(localAddr netip.Addr) (ifIdx int, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return -1, err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return -1, err
		}
		for _, a := range addrs {
			switch ipAddr := a.(type) {
			case *net.IPNet:
				if ipAddr.IP.Equal(localAddr.AsSlice()) {
					return i.Index, nil
				}
			}
		}
	}
	return -1, nil
}

func getLinkByRemoteAddr(remoteAddr netip.Addr) (ifIdx int, err error) {
	routes, err := netlink.RouteGet(remoteAddr.AsSlice())
	if err != nil {
		return -1, err
	}
	if len(routes) == 0 {
		return -1, fmt.Errorf("no route to IP: %v", remoteAddr)
	}
	if len(routes) > 1 {
		return -1, fmt.Errorf("multiple routes to IP %v", remoteAddr)
	}
	return routes[0].LinkIndex, nil
}

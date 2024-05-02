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
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ebpf"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// default synchronise time for the controller to sync with BPF maps
	defaultResyncTime = 2 * time.Second

	groupAddrField = "groupAddress"
	remoteSubField = "remoteSubscriber"
	localSubField  = "localSubscriber"
)

// addrMapType generic map definition for multicast group addresses and node IP addresses.
type addrMapType map[netip.Addr]struct{}

type MulticastManagerParams struct {
	cell.In

	Logger                 logrus.FieldLogger
	LC                     cell.Lifecycle
	JobGroup               job.Group
	Clientset              k8sClient.Clientset
	Cfg                    maps_multicast.Config
	TunnelConfig           tunnel.Config
	MulticastMaps          maps_multicast.GroupV4Map
	MulticastGroupResource resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastGroup]
	MulticastNodeResource  resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastNode]
	LocalNodeStore         *node.LocalNodeStore
	EndpointResource       resource.Resource[*k8sTypes.CiliumEndpoint]
}

type MulticastManager struct {
	Logger         logrus.FieldLogger
	LC             cell.Lifecycle
	JobGroup       job.Group
	LocalNodeStore *node.LocalNodeStore

	// maps_multicast objects
	Cfg           maps_multicast.Config
	MulticastMaps maps_multicast.GroupV4Map

	// K8s resources
	MulticastGroupResource resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastGroup]
	MulticastGroupStore    resource.Store[*isovalent_api_v1alpha1.IsovalentMulticastGroup]
	MulticastNodeClient    isovalent_client_v1alpha1.IsovalentMulticastNodeInterface
	MulticastNodeResource  resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastNode]
	MulticastNodeStore     resource.Store[*isovalent_api_v1alpha1.IsovalentMulticastNode]
	EndpointResource       resource.Resource[*k8sTypes.CiliumEndpoint]

	// local state
	reconcileCh  chan struct{}
	groupsSyncCh chan struct{}

	// node metadata
	nodeName string
	nodeIP   string

	// ifindex of vxlan device
	ciliumVxlanIfIndex int

	// nodeEndpoints is node local endpoint metadata.
	// This state is populated from k8sTypes.CiliumEndpoint events.
	// Key is namespaced name of resource object and value is map of IPv4 addresses associated with that endpoint.
	nodeEndpoints map[types.NamespacedName]map[netip.Addr]struct{}
}

func newMulticastManager(p MulticastManagerParams) (*MulticastManager, error) {
	if !p.Cfg.MulticastEnabled {
		return nil, nil
	}

	// check if maps initialized properly.
	if p.MulticastMaps == nil {
		return nil, fmt.Errorf("multicast maps failed to initialize, cannot continue")
	}

	// check if vxlan is enabled
	if p.TunnelConfig.Protocol() != tunnel.VXLAN {
		return nil, fmt.Errorf("unsupported tunnel protocol for multicast. Expected vxlan, got %q", p.TunnelConfig.Protocol().String())
	}

	mm := &MulticastManager{
		Logger:                 p.Logger,
		LC:                     p.LC,
		Cfg:                    p.Cfg,
		MulticastMaps:          p.MulticastMaps,
		MulticastGroupResource: p.MulticastGroupResource,
		MulticastNodeClient:    p.Clientset.IsovalentV1alpha1().IsovalentMulticastNodes(),
		MulticastNodeResource:  p.MulticastNodeResource,
		LocalNodeStore:         p.LocalNodeStore,
		EndpointResource:       p.EndpointResource,
		reconcileCh:            make(chan struct{}, 1),
		groupsSyncCh:           make(chan struct{}, 1),
		nodeEndpoints:          make(map[types.NamespacedName]map[netip.Addr]struct{}),
	}

	p.JobGroup.Add(
		job.OneShot("multicast-main", func(ctx context.Context, health cell.Health) (err error) {
			mm.MulticastGroupStore, err = mm.MulticastGroupResource.Store(ctx)
			if err != nil {
				return
			}

			mm.MulticastNodeStore, err = mm.MulticastNodeResource.Store(ctx)
			if err != nil {
				return
			}

			// initialize local node metadata
			localNode, err := mm.LocalNodeStore.Get(ctx)
			if err != nil {
				return err
			}

			mm.nodeName = localNode.Name
			mm.nodeIP = localNode.GetNodeIP(false).String() // Get IPv4 node IP
			if mm.nodeIP == "" {
				return fmt.Errorf("failed to get node IP")
			}

			// store initialized, trigger first reconcile
			mm.triggerReconciler()

			// blocking
			mm.Run(ctx)

			return nil
		}, job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second})),

		job.OneShot("multicast-group-observer", func(ctx context.Context, health cell.Health) error {
			for e := range mm.MulticastGroupResource.Events(ctx) {
				if e.Kind == resource.Sync {
					// Send signal to m.Run that groups are synced.
					// If we receive multiple sync events, m.Run will only listen to first one.
					// We don't want to block here in that case, hence using select.
					select {
					case mm.groupsSyncCh <- struct{}{}:
					default:
					}
				}

				mm.triggerReconciler()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("multicast-node-observer", func(ctx context.Context, health cell.Health) error {
			for e := range mm.MulticastNodeResource.Events(ctx) {
				mm.triggerReconciler()
				e.Done(nil)
			}
			return nil
		}),

		// TODO remove this timer based reconciler once we have event based updates from BPF
		job.OneShot("timer-based-reconciler", func(ctx context.Context, health cell.Health) error {
			ticker := time.NewTicker(defaultResyncTime)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					mm.triggerReconciler()
				}
			}
		}),
	)

	p.Logger.Info("Multicast manager initialized")

	return mm, nil
}

func (m *MulticastManager) triggerReconciler() {
	select {
	case m.reconcileCh <- struct{}{}:
	default:
	}
}

func (m *MulticastManager) Run(ctx context.Context) {
	m.Logger.Info("Starting multicast manager")
	defer m.Logger.Info("Stopping multicast manager")

	// sync endpoints
	endpointEvents := m.syncEndpoints(ctx)

	// wait for groups to sync
	<-m.groupsSyncCh

	m.Logger.Info("Initial sync completed")

	for {
		select {
		case <-ctx.Done():
			return

		case <-m.reconcileCh:
			err := m.reconcile(ctx)
			if err != nil {
				m.Logger.WithError(err).Error("Failed to reconcile multicast groups")
			}

		case e, ok := <-endpointEvents:
			if !ok {
				return
			}
			err := m.updateEndpoint(e)
			if err != nil {
				m.Logger.WithError(err).Error("Failed to update endpoints")
			}
			e.Done(err)
		}
	}
}

// syncEndpoints gets all endpoints till sync is done from CiliumEndpoint resource.
func (m *MulticastManager) syncEndpoints(ctx context.Context) <-chan resource.Event[*k8sTypes.CiliumEndpoint] {
	endpointEvents := m.EndpointResource.Events(ctx)

loop:
	for e := range endpointEvents {
		switch e.Kind {
		case resource.Sync:
			e.Done(nil)
			break loop

		case resource.Upsert:
			if e.Object.Networking == nil || e.Object.Networking.NodeIP != m.nodeIP {
				// skip endpoints of other nodes or if networking field is not set.
				e.Done(nil)
				continue loop
			}

			namespacedName := GetEndpointNamespacedName(e.Object)

			_, exist := m.nodeEndpoints[namespacedName]
			if !exist {
				m.nodeEndpoints[namespacedName] = make(map[netip.Addr]struct{})
			}

			for _, addr := range e.Object.Networking.Addressing {
				v4addr, err := netip.ParseAddr(addr.IPV4)
				if err != nil {
					continue
				}

				if v4addr.Is4() {
					m.nodeEndpoints[namespacedName][v4addr] = struct{}{}
					m.Logger.WithField("IP", v4addr).Debug("Adding endpoint IP to multicast manager")
				}
			}
		}

		e.Done(nil)
	}

	return endpointEvents
}

func (m *MulticastManager) updateEndpoint(e resource.Event[*k8sTypes.CiliumEndpoint]) error {
	if e.Kind == resource.Sync || e.Object == nil {
		return nil
	}

	if e.Object.Networking == nil || e.Object.Networking.NodeIP != m.nodeIP {
		return nil
	}

	// endpoint is identified by namespace and name of the object
	namespacedName := GetEndpointNamespacedName(e.Object)

	switch e.Kind {
	case resource.Upsert:
		existingIPs, exists := m.nodeEndpoints[namespacedName]
		if !exists {
			m.nodeEndpoints[namespacedName] = make(map[netip.Addr]struct{})
		}

		for _, addr := range e.Object.Networking.Addressing {
			v4addr, err := netip.ParseAddr(addr.IPV4)
			if err != nil {
				continue
			}

			if v4addr.Is4() {
				m.nodeEndpoints[namespacedName][v4addr] = struct{}{}
				m.Logger.WithField("IP", v4addr).Debug("Adding endpoint IP to multicast manager")
			}
		}

		for prevIP := range existingIPs {
			found := false
			for _, addr := range e.Object.Networking.Addressing {
				v4addr, err := netip.ParseAddr(addr.IPV4)
				if err != nil {
					continue
				}

				if v4addr.Compare(prevIP) == 0 {
					found = true
					break
				}
			}

			if !found {
				delete(m.nodeEndpoints[namespacedName], prevIP)
				m.Logger.WithField("IP", prevIP).Debug("Removing endpoint IP from multicast manager")
			}
		}

	case resource.Delete:
		// log deleted endpoints
		for addr := range m.nodeEndpoints[namespacedName] {
			m.Logger.WithField("IP", addr).Debug("Removing endpoint IP from multicast manager")
		}

		delete(m.nodeEndpoints, namespacedName)

		// some local endpoints are deleted, we should reconcile to remove any local subscribers
		m.triggerReconciler()
	}

	return nil
}

func (m *MulticastManager) reconcile(ctx context.Context) (err error) {
	// 0. populate vxlan ifindex if not already populated
	if m.ciliumVxlanIfIndex == 0 {
		m.ciliumVxlanIfIndex, err = GetIfIndex(ciliumDefaults.VxlanDevice)
		if err != nil {
			return fmt.Errorf("failed to populate ifindex of vxlan device %s: %w", ciliumDefaults.VxlanDevice, err)
		}
	}

	// 1. reconcile groups
	err = m.reconcileGroups()
	if err != nil {
		return err
	}

	// 2. reconcile remote subscribers in each group
	err = m.reconcileRemoteSubscribers()
	if err != nil {
		return err
	}

	// 3. remove any stale local subscribers
	err = m.removeStaleLocalSubscribers()
	if err != nil {
		return err
	}

	// 4. update node status with groups which have local subscribers
	return m.updateNodeStatus(ctx)
}

func (m *MulticastManager) reconcileGroups() (err error) {
	var (
		bpfGroups, k8sGroups addrMapType
	)

	bpfGroups, err = m.getGroupsFromBPF()
	if err != nil {
		return err
	}

	k8sGroups, err = m.getGroupsFromStore()
	if err != nil {
		return err
	}

	return m.reconcileGroupsInBPF(bpfGroups, k8sGroups)
}

func (m *MulticastManager) reconcileGroupsInBPF(fromBPF, fromK8s addrMapType) (err error) {
	var (
		toAdd, toDelete []netip.Addr
	)

	// populate to add and to delete groups
	for addr := range fromK8s {
		if _, exists := fromBPF[addr]; !exists {
			toAdd = append(toAdd, addr)
		}
	}

	for addr := range fromBPF {
		if _, exists := fromK8s[addr]; !exists {
			toDelete = append(toDelete, addr)
		}
	}

	// action add and delete groups
	for _, groupAddr := range toAdd {
		err = m.MulticastMaps.Insert(groupAddr)
		if err != nil {
			return err
		}

		m.Logger.WithFields(logrus.Fields{
			groupAddrField: groupAddr,
		}).Info("Multicast group added")
	}

	for _, groupAddr := range toDelete {
		err = m.MulticastMaps.Delete(groupAddr)
		if err != nil {
			return err
		}

		m.Logger.WithFields(logrus.Fields{
			groupAddrField: groupAddr,
		}).Info("Multicast group deleted")
	}

	return nil
}

// reconcileRemoteSubscribers reconciles BPF maps with known remote subscribers from k8s IsovalentMulticastNode objects.
func (m *MulticastManager) reconcileRemoteSubscribers() (err error) {
	groups, err := m.getGroupRemoteSubscribersFromK8s()
	if err != nil {
		return err
	}

	for groupAddr, fromK8s := range groups {
		fromBPF, err := m.getRemoteSubscribersFromBPF(groupAddr)
		if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
			// corner case if group does not exist in BPF, we ignore that group.
			m.Logger.WithError(err).WithField(groupAddrField, groupAddr).Warn("Group not found in BPF map")
			continue
		}
		if err != nil {
			return err
		}

		err = m.reconcileRemoteSubscribersInBPF(groupAddr, fromK8s, fromBPF)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *MulticastManager) reconcileRemoteSubscribersInBPF(groupAddr netip.Addr, fromK8s, fromBPF addrMapType) error {
	var (
		toAdd, toDelete []netip.Addr
	)

	// populate to add and to delete subscribers
	for addr := range fromK8s {
		if _, exists := fromBPF[addr]; !exists {
			toAdd = append(toAdd, addr)
		}
	}

	for addr := range fromBPF {
		if _, exists := fromK8s[addr]; !exists {
			toDelete = append(toDelete, addr)
		}
	}

	// update BPF map
	subscriberMap, err := m.MulticastMaps.Lookup(groupAddr)
	if err != nil {
		return err
	}

	for _, addr := range toAdd {
		sub := &maps_multicast.SubscriberV4{
			SAddr:    addr,
			IsRemote: true,
			Ifindex:  uint32(m.ciliumVxlanIfIndex),
		}

		err = subscriberMap.Insert(sub)
		if err != nil {
			return err
		}

		m.Logger.WithFields(logrus.Fields{
			groupAddrField: groupAddr,
			remoteSubField: addr,
		}).Info("Remote subscriber added")
	}

	for _, addr := range toDelete {
		err = subscriberMap.Delete(addr)
		if err != nil {
			return err
		}

		m.Logger.WithFields(logrus.Fields{
			groupAddrField: groupAddr,
			remoteSubField: addr,
		}).Info("Remote subscriber deleted")
	}

	return nil
}

// updateNodeStatus updates IsovalentMulticastNode object status with known local groups from BPF maps.
func (m *MulticastManager) updateNodeStatus(ctx context.Context) (err error) {
	newStatus, err := m.getNodeStatusFromBPF()
	if err != nil {
		return err
	}

	newNode := &isovalent_api_v1alpha1.IsovalentMulticastNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: m.nodeName,
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastNodeSpec{
			NodeIP: m.nodeIP,
		},
		Status: newStatus,
	}

	currentNode, exists, err := m.MulticastNodeStore.GetByKey(resource.Key{Name: m.nodeName})
	if err != nil {
		return err
	}

	switch {
	case exists && currentNode.Status.DeepEqual(&newStatus):
		// nothing to do
		return nil

	case exists:
		// update node status
		currentNode.Status = newStatus
		_, err = m.MulticastNodeClient.UpdateStatus(ctx, currentNode, metav1.UpdateOptions{})
		m.Logger.WithFields(logrus.Fields{
			logfields.NodeName:  m.nodeName,
			logfields.K8sNodeIP: m.nodeIP,
		}).Info("Updating IsovalentMulticastNode")

	default:
		// create new node object
		_, err = m.MulticastNodeClient.Create(ctx, newNode, metav1.CreateOptions{})
		if err != nil && k8sErrors.IsAlreadyExists(err) {
			// it is possible that newly created object is not yet present in the store, and we try to create it again.
			// in that case, we can ignore the error.
			return nil
		}

		m.Logger.WithFields(logrus.Fields{
			logfields.NodeName:  m.nodeName,
			logfields.K8sNodeIP: m.nodeIP,
		}).Info("Creating IsovalentMulticastNode")
	}

	return err
}

func (m *MulticastManager) getNodeStatusFromBPF() (isovalent_api_v1alpha1.IsovalentMulticastNodeStatus, error) {
	// get local groups from BPF maps
	localGroupAndSubs, err := m.getLocalSubscribersFromBPF()
	if err != nil {
		return isovalent_api_v1alpha1.IsovalentMulticastNodeStatus{}, err
	}

	var localGroups []netip.Addr
	for groupAddr := range localGroupAndSubs {
		localGroups = append(localGroups, groupAddr)
	}

	// sort groups
	sort.Slice(localGroups, func(i, j int) bool {
		return localGroups[i].Compare(localGroups[j]) < 0
	})

	// marshal data into IsovalentMulticastNodeStatus
	multicastSubscribers := make([]isovalent_api_v1alpha1.MulticastNodeSubscriberData, 0, len(localGroups))
	for _, groupAddr := range localGroups {
		multicastSubscribers = append(multicastSubscribers, isovalent_api_v1alpha1.MulticastNodeSubscriberData{
			GroupAddr: isovalent_api_v1alpha1.MulticastGroupAddr(groupAddr.String()),
		})
	}

	newNodeStatus := isovalent_api_v1alpha1.IsovalentMulticastNodeStatus{
		MulticastSubscribers: multicastSubscribers,
	}

	return newNodeStatus, nil
}

// getGroupsFromStore returns a map of multicast group addresses from k8s IsovalentMulticastGroup objects.
func (m *MulticastManager) getGroupsFromStore() (addrMapType, error) {
	res := make(addrMapType)

	groupObjs := m.MulticastGroupStore.List()
	for _, groupObj := range groupObjs {
		for _, groupAddr := range groupObj.Spec.GroupAddrs {
			addr, err := ParseMulticastAddr(string(groupAddr))
			if err != nil {
				return nil, err
			}
			res[addr] = struct{}{}
		}
	}

	return res, nil
}

func (m *MulticastManager) getGroupsFromBPF() (addrMapType, error) {
	res := make(addrMapType)

	groupAddrs, err := m.MulticastMaps.List()
	if err != nil {
		return nil, err
	}

	for _, groupAddr := range groupAddrs {
		res[groupAddr] = struct{}{}
	}

	return res, nil
}

// getGroupRemoteSubscribersFromK8s returns remote subscribers for all groups from k8s IsovalentMulticastNode objects.
func (m *MulticastManager) getGroupRemoteSubscribersFromK8s() (map[netip.Addr]addrMapType, error) {
	res := make(map[netip.Addr]addrMapType) // key is group address

	// populate expected groups from store.
	groupAddrs, err := m.getGroupsFromStore()
	if err != nil {
		return nil, err
	}
	for groupAddr := range groupAddrs {
		res[groupAddr] = make(addrMapType)
	}

	// get all node objects and populate remote subscribers for each group
	nodeObjs := m.MulticastNodeStore.List()
	for _, nodeObj := range nodeObjs {
		// skip self
		if nodeObj.Name == m.nodeName {
			continue
		}

		// parse node IP
		nodeAddr, err := netip.ParseAddr(nodeObj.Spec.NodeIP)
		if err != nil {
			return nil, err
		}

		for _, groupData := range nodeObj.Status.MulticastSubscribers {
			nodeGroupAddr, err := ParseMulticastAddr(string(groupData.GroupAddr))
			if err != nil {
				return nil, err
			}

			// Add remote node IP to group, only if group exist.
			// Group list from k8s is source of truth, if there are any extra groups in Status field of Node objects,
			// they can be ignored. Eventually it will be removed from Status field.
			_, exists := res[nodeGroupAddr]
			if exists {
				res[nodeGroupAddr][nodeAddr] = struct{}{}
			}
		}
	}

	return res, nil
}

// getRemoteSubscribersFromBPF returns a map of remote subscribers for a multicast group from BPF maps.
func (m *MulticastManager) getRemoteSubscribersFromBPF(groupAddr netip.Addr) (addrMapType, error) {
	res := make(addrMapType)

	subscriberMap, err := m.MulticastMaps.Lookup(groupAddr)
	if err != nil {
		return nil, err
	}

	subscribers, err := subscriberMap.List()
	if err != nil {
		return nil, err
	}

	for _, subscriber := range subscribers {
		if subscriber.IsRemote {
			res[subscriber.SAddr] = struct{}{}
		}
	}

	return res, nil
}

// getLocalSubscribersFromBPF returns a list of multicast group addresses and local subscribers from BPF maps.
func (m *MulticastManager) getLocalSubscribersFromBPF() (map[netip.Addr][]netip.Addr, error) {
	var res = make(map[netip.Addr][]netip.Addr)

	groupAddrs, err := m.MulticastMaps.List()
	if err != nil {
		return nil, err
	}

	for _, groupAddr := range groupAddrs {
		subscriberMap, err := m.MulticastMaps.Lookup(groupAddr)
		if err != nil {
			return nil, err
		}

		subscribers, err := subscriberMap.List()
		if err != nil {
			return nil, err
		}

		for _, subscriber := range subscribers {
			if !subscriber.IsRemote {
				res[groupAddr] = append(res[groupAddr], subscriber.SAddr)
			}
		}
	}

	return res, nil
}

func ParseMulticastAddr(addrStr string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return netip.Addr{}, err
	}

	if !addr.Is4() || !addr.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("invalid multicast IPv4 address")
	}

	return addr, nil
}

// GetIfIndex returns ifindex of the given device.
func GetIfIndex(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}

	return link.Attrs().Index, nil
}

// GetEndpointNamespacedName returns key for CiliumEndpoint object.
func GetEndpointNamespacedName(obj *k8sTypes.CiliumEndpoint) types.NamespacedName {
	return types.NamespacedName{
		Namespace: obj.Namespace,
		Name:      obj.Name,
	}
}

// removeStaleLocalSubscribers removes any local subscribers from BPF maps which are not present in nodeEndpoints.
func (m *MulticastManager) removeStaleLocalSubscribers() error {
	// get local subscribers from BPF maps
	localGroupAndSubs, err := m.getLocalSubscribersFromBPF()
	if err != nil {
		return err
	}

	for groupAddr, subscribers := range localGroupAndSubs {
		subscriberMap, err := m.MulticastMaps.Lookup(groupAddr)
		if err != nil {
			return err
		}

		for _, subAddr := range subscribers {
			found := false

			for _, endpointIPs := range m.nodeEndpoints {
				_, exists := endpointIPs[subAddr]
				if exists {
					found = true
					break
				}
			}

			if !found {
				err = subscriberMap.Delete(subAddr)
				if err != nil {
					return err
				}
				m.Logger.WithFields(logrus.Fields{
					groupAddrField: groupAddr,
					localSubField:  subAddr,
				}).Info("Local subscriber deleted")
			}
		}
	}

	return nil
}

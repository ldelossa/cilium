//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"go4.org/netipx"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	enterprise_tables "github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/egressipconf"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway-ha")
	// GatewayNotFoundIPv4 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv4 = netip.MustParseAddr("0.0.0.0")
	// ExcludedCIDRIPv4 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv4 = netip.MustParseAddr("0.0.0.1")
	// EgressIPNotFoundIPv4 is a special IP value used as egressIP in the BPF policy map
	// to indicate no egressIP was found for the given policy
	EgressIPNotFoundIPv4 = netip.IPv4Unspecified()
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgatewayha",
	"Egress Gateway allows originating traffic from specific IPv4 addresses",

	egressipconf.Cell,

	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
)

type eventType int

const (
	eventNone = eventType(1 << iota)
	eventK8sSyncDone
	eventAddPolicy
	eventDeletePolicy
	eventUpdateEndpoint
	eventDeleteEndpoint
	eventUpdateNode
	eventDeleteNode
)

type Config struct {
	// Healthcheck timeout after which an egress gateway is marked not healthy.
	// This also configures the frequency of probes to a value of healthcheckTimeout / 2
	// Deprecated, has no effect, and will removed in v1.16"
	EgressGatewayHAHealthcheckTimeout time.Duration

	// Default amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayHAReconciliationTriggerInterval time.Duration
}

var defaultConfig = Config{
	EgressGatewayHAHealthcheckTimeout:            1 * time.Second,
	EgressGatewayHAReconciliationTriggerInterval: 1 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-ha-healthcheck-timeout", def.EgressGatewayHAHealthcheckTimeout, "Healthcheck timeout after which an egress gateway is marked not healthy. This also configures the frequency of probes to a value of healthcheckTimeout / 2")
	flags.MarkDeprecated("egress-gateway-ha-healthcheck-timeout", "This option is deprecated, has no effect, and will be removed in v1.16")

	flags.Duration("egress-gateway-ha-reconciliation-trigger-interval", def.EgressGatewayHAReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// endpoints allows reading endpoint CRD from k8s.
	endpoints resource.Resource[*k8sTypes.CiliumEndpoint]

	// nodesResource allows reading node CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// nodeDataStore stores node names to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// nodesByIP stores node IPs to node mapping
	nodesByIP map[string]nodeTypes.Node

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// policyConfigsBySourceIP stores slices of policy configs indexed by
	// the policies' source/endpoint IPs
	policyConfigsBySourceIP map[string][]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap communicates the active policies to the dapath.
	policyMap egressmapha.PolicyMap

	// ctMap stores EGW specific conntrack entries.
	ctMap egressmapha.CtMap

	// reconciliationTriggerInterval is the amount of time between triggers
	// of reconciliations are invoked
	reconciliationTriggerInterval time.Duration

	// eventsBitmap is a bitmap that tracks which type of events has been
	// received by the manager (e.g. node added or policy removed) since the
	// last invocation of the reconciliation logic
	eventsBitmap eventType

	// reconciliationTrigger is the trigger used to reconcile the state of
	// the node with the desired egress gateway state.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger

	// reconciliationEventsCount keeps track of how many reconciliation
	// events have occoured
	reconciliationEventsCount atomic.Uint64

	localNodeStore *node.LocalNodeStore

	sysctl sysctl.Sysctl

	// bgpSignaler is used to signal reconciliation events to the BGP Control Plane
	bgpSignaler *signaler.BGPCPSignaler

	// egressConfigsByPolicy stores all the configurations (addr and iface) for IPAM
	// allocations entitled to the local node, as reported in each Egress Group Status
	// of the IEGPs.
	// The key of the map is the policy reporting the address allocation, the value is
	// the set of configuration pairs <egressIP, net_inteface> for that policy.
	egressConfigsByPolicy map[policyID]sets.Set[gwEgressIPConfig]

	egressIPTable statedb.RWTable[*enterprise_tables.EgressIPEntry]

	db *statedb.DB
}

type Params struct {
	cell.In

	Config            Config
	DaemonConfig      *option.DaemonConfig
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         egressmapha.PolicyMap
	Policies          resource.Resource[*Policy]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	Nodes             resource.Resource[*cilium_api_v2.CiliumNode]
	CtMap             egressmapha.CtMap
	LocalNodeStore    *node.LocalNodeStore
	Sysctl            sysctl.Sysctl
	BGPSignaler       *signaler.BGPCPSignaler

	DB            *statedb.DB
	EgressIPTable statedb.RWTable[*enterprise_tables.EgressIPEntry]

	Lifecycle cell.Lifecycle
}

func NewEgressGatewayManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
	tunnel.EnablerOut
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableIPv4EgressGatewayHA {
		return out, nil
	}

	if dcfg.IdentityAllocationMode != option.IdentityAllocationModeCRD {
		return out, fmt.Errorf("egress gateway is not supported in %s identity allocation mode", dcfg.IdentityAllocationMode)
	}

	if dcfg.EnableHighScaleIPcache {
		return out, errors.New("egress gateway is not supported in high scale IPcache mode")
	}

	if dcfg.EnableCiliumEndpointSlice {
		return out, errors.New("egress gateway is not supported in combination with the CiliumEndpointSlice feature")
	}

	if !dcfg.EnableIPv4Masquerade || !dcfg.EnableBPFMasquerade {
		return out, fmt.Errorf("egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	}

	if !p.DaemonConfig.HealthCheckingEnabled() {
		return out, fmt.Errorf("egress gateway HA requires healthchecking to be enabled")
	}

	out.Manager, err = newEgressGatewayManager(p)
	if err != nil {
		return out, err
	}

	out.NodeDefines = map[string]string{
		"ENABLE_EGRESS_GATEWAY_HA": "1",
	}

	out.EnablerOut = tunnel.NewEnabler(true)

	return out, nil
}

func newEgressGatewayManager(p Params) (*Manager, error) {
	manager := &Manager{
		nodeDataStore:                 make(map[string]nodeTypes.Node),
		policyConfigs:                 make(map[policyID]*PolicyConfig),
		policyConfigsBySourceIP:       make(map[string][]*PolicyConfig),
		egressConfigsByPolicy:         make(map[policyID]sets.Set[gwEgressIPConfig]),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		identityAllocator:             p.IdentityAllocator,
		reconciliationTriggerInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
		policyMap:                     p.PolicyMap,
		policies:                      p.Policies,
		endpoints:                     p.Endpoints,
		ciliumNodes:                   p.Nodes,
		ctMap:                         p.CtMap,
		localNodeStore:                p.LocalNodeStore,
		sysctl:                        p.Sysctl,
		bgpSignaler:                   p.BGPSignaler,
		db:                            p.DB,
		egressIPTable:                 p.EgressIPTable,
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "egress_gateway_ha_reconciliation",
		MinInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			reason := strings.Join(reasons, ", ")
			log.WithField(logfields.Reason, reason).Debug("reconciliation triggered")

			manager.Lock()
			defer manager.Unlock()

			manager.reconcileLocked()
		},
	})
	if err != nil {
		return nil, err
	}

	manager.reconciliationTrigger = t

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				manager.processEvents(ctx)
			}()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			wg.Wait()
			return nil
		},
	})

	return manager, nil
}

func (manager *Manager) setEventBitmap(events ...eventType) {
	for _, e := range events {
		manager.eventsBitmap |= e
	}
}

func (manager *Manager) eventBitmapIsSet(events ...eventType) bool {
	for _, e := range events {
		if manager.eventsBitmap&e != 0 {
			return true
		}
	}

	return false
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (manager *Manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	identityCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(identityCtx); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %w", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(identityCtx, identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// processEvents spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) processEvents(ctx context.Context) {
	var policySync, endpointSync, nodeSync bool
	maybeTriggerReconcile := func() {
		if !policySync || !endpointSync || !nodeSync {
			return
		}

		manager.Lock()
		defer manager.Unlock()

		if manager.allCachesSynced {
			return
		}

		manager.allCachesSynced = true
		manager.setEventBitmap(eventK8sSyncDone)
		manager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	endpointsRateLimit := workqueue.NewItemExponentialFailureRateLimiter(time.Millisecond*20, time.Minute*20)

	policyEvents := manager.policies.Events(ctx)
	endpointEvents := manager.endpoints.Events(ctx, resource.WithRateLimiter(endpointsRateLimit))
	nodeEvents := manager.ciliumNodes.Events(ctx)

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-policyEvents:
			if event.Kind == resource.Sync {
				policySync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handlePolicyEvent(event)
			}

		case event := <-endpointEvents:
			if event.Kind == resource.Sync {
				endpointSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleEndpointEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleNodeEvent(event)
			}
		}
	}
}

func (manager *Manager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := manager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		manager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

// Event handlers

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddEgressPolicy(policy *Policy) error {
	logger := log.WithFields(logrus.Fields{
		logfields.IsovalentEgressGatewayPolicyName: policy.Name,
		logfields.K8sUID: policy.UID,
	})

	if policy.Status.ObservedGeneration != policy.GetGeneration() {
		logger.Debug("Received policy whose GroupStatuses has not yet been updated by the operator, ignoring it")
		return nil
	}

	config, err := ParseIEGP(policy)
	if err != nil {
		logger.WithError(err).Warn("Failed to parse IsovalentEgressGatewayPolicy")
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Debug("Added IsovalentEgressGatewayPolicy")
	} else {
		logger.Debug("Updated IsovalentEgressGatewayPolicy")
	}

	config.updateMatchedEndpointIDs(manager.epDataStore)

	manager.policyConfigs[config.id] = config

	manager.setEventBitmap(eventAddPolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy added")
	return nil
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (manager *Manager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseIEGPConfigID(policy)

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.IsovalentEgressGatewayPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete IsovalentEgressGatewayPolicy: policy not found")
	}

	logger.Debug("Deleted IsovalentEgressGatewayPolicy")

	delete(manager.policyConfigs, configID)

	manager.setEventBitmap(eventDeletePolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy deleted")
}

func (manager *Manager) addEndpoint(endpoint *k8sTypes.CiliumEndpoint) error {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
		logfields.K8sUID:          endpoint.UID,
	})

	if endpoint.Identity == nil {
		logger.Warning("Endpoint is missing identity metadata, skipping update to egress policy.")
		return nil
	}

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.WithError(err).
			Warning("Failed to get identity labels for endpoint")
		return err
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return nil
	}

	if _, ok := manager.epDataStore[epData.id]; ok {
		logger.Debug("Updated CiliumEndpoint")
	} else {
		logger.Debug("Added CiliumEndpoint")
	}

	manager.epDataStore[epData.id] = epData

	manager.setEventBitmap(eventUpdateEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint updated")

	return nil
}

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
		logfields.K8sUID:          endpoint.UID,
	})

	logger.Debug("Deleted CiliumEndpoint")
	delete(manager.epDataStore, endpoint.UID)

	manager.setEventBitmap(eventDeleteEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint deleted")
}

func (manager *Manager) handleEndpointEvent(event resource.Event[*k8sTypes.CiliumEndpoint]) {
	endpoint := event.Object

	if event.Kind == resource.Upsert {
		event.Done(manager.addEndpoint(endpoint))
	} else {
		manager.deleteEndpoint(endpoint)
		event.Done(nil)
	}
}

// handleNodeEvent takes care of node upserts and removals.
func (manager *Manager) handleNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := nodeTypes.ParseCiliumNode(event.Object)

	manager.Lock()
	defer manager.Unlock()

	if event.Kind == resource.Upsert {
		manager.nodeDataStore[node.Name] = node

		manager.setEventBitmap(eventUpdateNode)
		manager.reconciliationTrigger.TriggerWithReason("CiliumNode updated")
	} else {
		delete(manager.nodeDataStore, node.Name)

		manager.setEventBitmap(eventDeleteNode)
		manager.reconciliationTrigger.TriggerWithReason("CiliumNode deleted")
	}
}

func (manager *Manager) updatePoliciesMatchedEndpointIDs() {
	for _, policy := range manager.policyConfigs {
		policy.updateMatchedEndpointIDs(manager.epDataStore)
	}
}

func (manager *Manager) updatePoliciesBySourceIP() {
	manager.policyConfigsBySourceIP = make(map[string][]*PolicyConfig)

	for _, policy := range manager.policyConfigs {
		for _, ep := range policy.matchedEndpoints {
			for _, epIP := range ep.ips {
				ip := epIP.String()
				manager.policyConfigsBySourceIP[ip] = append(manager.policyConfigsBySourceIP[ip], policy)
			}
		}
	}
}

func (manager *Manager) updateNodesByIP() {
	manager.nodesByIP = make(map[string]nodeTypes.Node)

	for _, node := range manager.nodeDataStore {
		for _, ipAddress := range node.IPAddresses {
			if ipAddress.AddrType() == addressing.NodeInternalIP {
				manager.nodesByIP[ipAddress.ToString()] = node
			}
		}
	}
}

// policyMatches returns true if there exists at least one policy matching the
// given parameters.
//
// This method takes:
//   - a source IP: this is an optimization that allows to iterate only through
//     policies that reference an endpoint with the given source IP
//   - a callback function f: this function is invoked for each policy and for
//     each combination of the policy's endpoints and destination/excludedCIDRs.
//
// The callback f takes as arguments:
// - the given endpoint
// - the destination CIDR
// - a boolean value indicating if the CIDR belongs to the excluded ones
// - the gatewayConfig of the  policy
//
// This method returns true whenever the f callback matches one of the endpoint
// and CIDR tuples (i.e. whenever one callback invocation returns true)
func (manager *Manager) policyMatches(sourceIP netip.Addr, f func(*endpointMetadata, netip.Prefix, bool, *gatewayConfig) bool) bool {
	for _, policy := range manager.policyConfigsBySourceIP[sourceIP.String()] {
		if policy.matches(f) {
			return true
		}
	}

	return false
}

func (manager *Manager) removeStaleEgressIPConfigs() {
	for policyID := range manager.egressConfigsByPolicy {
		if _, found := manager.policyConfigs[policyID]; found {
			continue
		}

		// policy has been removed, so remove egress IPs and routes too
		manager.removePolicyEgressIPs(manager.egressConfigsByPolicy[policyID])
		delete(manager.egressConfigsByPolicy, policyID)
	}
}

func (manager *Manager) removePolicyEgressIPs(egressIPs sets.Set[gwEgressIPConfig]) {
	txn := manager.db.WriteTxn(manager.egressIPTable)
	defer txn.Abort()

	for _, egressIP := range egressIPs.UnsortedList() {
		key := enterprise_tables.EgressIPKey{
			Addr:      egressIP.addr,
			Interface: egressIP.iface,
		}
		obj, _, found := manager.egressIPTable.Get(txn, enterprise_tables.EgressIPEntryIndex.Query(key))
		if !found {
			continue
		}
		if _, _, err := manager.egressIPTable.Delete(txn, obj); err != nil {
			log.WithFields(logrus.Fields{
				logfields.EgressIP:  egressIP.addr,
				logfields.Interface: egressIP.iface,
			}).WithError(err).Error("Failed to delete entry from egress-ips stateDB table")
		}
	}

	txn.Commit()
}

func (manager *Manager) regenerateGatewayConfigs() {
	for _, policyConfig := range manager.policyConfigs {
		policyConfig.regenerateGatewayConfig(manager)
	}
}

func (manager *Manager) relaxRPFilter() error {
	var sysSettings []tables.Sysctl
	ifSet := make(map[string]struct{})

	for _, pc := range manager.policyConfigs {
		if !pc.gatewayConfig.localNodeConfiguredAsGateway {
			continue
		}

		ifaceName := pc.gatewayConfig.ifaceName
		if _, ok := ifSet[ifaceName]; !ok {
			ifSet[ifaceName] = struct{}{}
			sysSettings = append(sysSettings, tables.Sysctl{
				Name:      fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifaceName),
				Val:       "2",
				IgnoreErr: false,
			})
		}
	}

	if len(sysSettings) == 0 {
		return nil
	}

	return manager.sysctl.ApplySettings(sysSettings)
}

func (manager *Manager) addMissingEgressRules() {
	egressPolicies := map[egressmapha.EgressPolicyKey4]egressmapha.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmapha.EgressPolicyKey4, val *egressmapha.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	addEgressRule := func(endpoint *endpointMetadata, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) {
		activeGatewayIPs, egressIP := gwc.gatewayConfigForEndpoint(manager, endpoint)
		if excludedCIDR {
			activeGatewayIPs = []netip.Addr{ExcludedCIDRIPv4}
		}

		for _, endpointIP := range endpoint.ips {
			policyKey := egressmapha.NewEgressPolicyKey4(endpointIP, dstCIDR)
			policyVal, policyPresent := egressPolicies[policyKey]

			if policyPresent && policyVal.Match(egressIP, activeGatewayIPs) {
				return
			}

			logger := log.WithFields(logrus.Fields{
				logfields.SourceIP:        endpointIP,
				logfields.DestinationCIDR: dstCIDR.String(),
				logfields.EgressIP:        egressIP,
				logfields.GatewayIPs:      joinStringers(activeGatewayIPs, ","),
			})

			if err := egressmapha.ApplyEgressPolicy(manager.policyMap, endpointIP, dstCIDR, egressIP, activeGatewayIPs); err != nil {
				logger.WithError(err).Error("Error applying egress gateway policy")
			} else {
				logger.Debug("Egress gateway policy applied")
			}
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDR(addEgressRule)
	}
}

// removeUnusedEgressRules is responsible for removing any entry in the egress policy BPF map which
// is not baked by an actual k8s IsovalentEgressGatewayPolicy.
func (manager *Manager) removeUnusedEgressRules() {
	egressPolicies := map[egressmapha.EgressPolicyKey4]egressmapha.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmapha.EgressPolicyKey4, val *egressmapha.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	for policyKey, policyVal := range egressPolicies {
		matchPolicy := func(endpoint *endpointMetadata, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) bool {
			activeGatewayIPs, egressIP := gwc.gatewayConfigForEndpoint(manager, endpoint)
			if excludedCIDR {
				activeGatewayIPs = []netip.Addr{ExcludedCIDRIPv4}
			}

			for _, endpointIP := range endpoint.ips {
				if policyKey.Match(endpointIP, dstCIDR) && policyVal.Match(egressIP, activeGatewayIPs) {
					return true
				}
			}

			return false
		}

		if manager.policyMatches(policyKey.GetSourceIP(), matchPolicy) {
			continue
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        policyKey.GetSourceIP(),
			logfields.DestinationCIDR: policyKey.GetDestCIDR().String(),
			logfields.EgressIP:        policyVal.GetEgressIP(),
			logfields.GatewayIPs:      joinStringers(policyVal.GetGatewayIPs(), ","),
		})

		if err := egressmapha.RemoveEgressPolicy(manager.policyMap, policyKey.GetSourceIP(), policyKey.GetDestCIDR()); err != nil {
			logger.WithError(err).Error("Error removing egress gateway policy")
		} else {
			logger.Debug("Egress gateway policy removed")
		}
	}
}

func (manager *Manager) removeExpiredCtEntries() {
	ctEntries := map[egressmapha.EgressCtKey4]egressmapha.EgressCtVal4{}
	manager.ctMap.IterateWithCallback(
		func(key *egressmapha.EgressCtKey4, val *egressmapha.EgressCtVal4) {
			ctEntries[*key] = *val
		})

	policyMatchesCtEntry := func(policy *PolicyConfig, ctKey *egressmapha.EgressCtKey4, ctVal *egressmapha.EgressCtVal4) bool {
		gatewayIP, ok := netipx.FromStdIP(ctVal.Gateway.IP())
		if !ok {
			log.Error("Cannot parse CT entry's gateway IP while removing expired entries")
			return false
		}

	nextDstCIDR:
		for _, dstCIDR := range policy.dstCIDRs {
			if !dstCIDR.Contains(ctKey.DestAddr.Addr()) {
				continue
			}

			for _, excludedCIDR := range policy.excludedCIDRs {
				if excludedCIDR.Contains(ctKey.DestAddr.Addr()) {
					continue nextDstCIDR
				}
			}

			// no need to check also endpointIP.Equal(endpointIP) as we are iterating
			// over the slice of policies returned by the
			// policyConfigsBySourceIP[ipRule.Src.IP.String()] map
			if slices.Contains(policy.gatewayConfig.healthyGatewayIPs, gatewayIP) {
				return true
			}
		}

		return false
	}

nextCtKey:
	for ctKey, ctVal := range ctEntries {
		for _, policyConfig := range manager.policyConfigsBySourceIP[ctKey.SourceAddr.IP().String()] {
			if policyMatchesCtEntry(policyConfig, &ctKey, &ctVal) {
				continue nextCtKey
			}
		}

		logger := log.WithFields(logrus.Fields{
			// TODO log the whole ctKey
			logfields.SourceIP:  ctKey.SourceAddr.IP(),
			logfields.GatewayIP: ctVal.Gateway.IP(),
		})

		if err := manager.ctMap.Delete(&ctKey); err != nil {
			logger.WithError(err).Error("Error removing egress gateway CT entry")
		} else {
			logger.Debug("Egress gateway CT entry removed")
		}
	}
}

// reconcileLocked is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileLocked() {
	if !manager.allCachesSynced {
		return
	}

	// on eventK8sSyncDone we need to update all caches unconditionally as
	// we don't know which k8s events/resources were received during the
	// initial k8s sync
	if manager.eventBitmapIsSet(eventK8sSyncDone) {
		manager.updatePoliciesMatchedEndpointIDs()
		manager.updatePoliciesBySourceIP()
		manager.updateNodesByIP()
	} else {
		if manager.eventBitmapIsSet(eventUpdateEndpoint, eventDeleteEndpoint, eventAddPolicy, eventDeletePolicy) {
			if manager.eventBitmapIsSet(eventUpdateEndpoint, eventDeleteEndpoint) {
				manager.updatePoliciesMatchedEndpointIDs()
			}
			manager.updatePoliciesBySourceIP()
		}

		if manager.eventBitmapIsSet(eventUpdateNode, eventDeleteNode) {
			manager.updateNodesByIP()
		}
	}

	manager.removeStaleEgressIPConfigs()

	if manager.eventBitmapIsSet(eventK8sSyncDone, eventAddPolicy, eventDeletePolicy, eventUpdateNode, eventDeleteNode) {
		manager.regenerateGatewayConfigs()

		// Sysctl updates are handled by a reconciler, with the initial update attempting to wait some time
		// for a synchronous reconciliation. Thus these updates are already resilient so in case of failure
		// our best course of action is to log the error and continue with the reconciliation.
		//
		// The rp_filter setting is only important for traffic originating from endpoints on the same host (i.e.
		// egw traffic being forwarded from a local Pod endpoint to the gateway on the same node).
		// Therefore, for the sake of resiliency, it is acceptable for EGW to continue reconciling gatewayConfigs
		// even if the rp_filter setting are failing.
		if err := manager.relaxRPFilter(); err != nil {
			log.WithError(err).Error("Error relaxing rp_filter for gateway interfaces. "+
				"Selected egress gateway interfaces require rp_filter settings to use loose mode (rp_filter=2) for gateway forwarding to work correctly. ",
				"This may cause connectivity issues for egress gateway traffic being forwarded through this node for Pods running on the same host. ")
		}
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingEgressRules()
	manager.removeUnusedEgressRules()

	// clear the events bitmap
	manager.eventsBitmap = 0

	// Remove stale CT entries. We keep entries that point at an inactive Gateway node,
	// as long as the node is healthy.
	manager.removeExpiredCtEntries()

	// Signal the BGP Control Plane
	manager.bgpSignaler.Event(struct{}{})

	manager.reconciliationEventsCount.Add(1)
}

// AdvertisedEgressIPs returns a map of policy to egress IPs, used by EGW polices selected by the provided policy selector,
// that should be advertised for this node as currently used egress IPs.
func (manager *Manager) AdvertisedEgressIPs(policySelector *slimv1.LabelSelector) (map[types.NamespacedName][]netip.Addr, error) {
	manager.Lock()
	defer manager.Unlock()

	selector, err := slimv1.LabelSelectorAsSelector(policySelector)
	if err != nil {
		return nil, err
	}

	egressIPs := make(map[types.NamespacedName][]netip.Addr)
	for _, policyConfig := range manager.policyConfigs {
		gwc := policyConfig.gatewayConfig
		if gwc.localNodeConfiguredAsGateway && selector.Matches(k8sLabels.Set(policyConfig.labels)) {
			egressIPs[policyConfig.id] = append(egressIPs[policyConfig.id], gwc.egressIP)
		}
	}
	return egressIPs, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

// OperatorCell provides an [OperatorManager] for consumption with hive.
var OperatorCell = cell.Module(
	"egressgatewayha-operator",
	"The Egress Gateway Operator manages cluster wide EGW state",
	cell.Config(defaultOperatorConfig),
	cell.Provide(NewEgressGatewayOperatorManager),
)

type OperatorConfig struct {
	// Amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayHAReconciliationTriggerInterval time.Duration
}

var defaultOperatorConfig = OperatorConfig{
	2 * time.Second,
}

func (def OperatorConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-ha-reconciliation-trigger-interval", def.EgressGatewayHAReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

type OperatorParams struct {
	cell.In

	Config        OperatorConfig
	DaemonConfig  *option.DaemonConfig
	Clientset     k8sClient.Clientset
	Policies      resource.Resource[*Policy]
	Nodes         resource.Resource[*cilium_api_v2.CiliumNode]
	Healthchecker healthcheck.Healthchecker

	Lifecycle cell.Lifecycle
}

type OperatorManager struct {
	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// clientset is a k8s clientset used to retrieve and update the IEGP
	// objects' status
	clientset k8sClient.Clientset

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// nodesResource allows reading node CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// nodeDataStore stores node name to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// nodesByIP stores node IP to node mapping
	nodesByIP map[string]nodeTypes.Node

	// gatewayNodeDatatStore stores all nodes that are acting as a gateway
	gatewayNodeDataStore map[string]nodeTypes.Node

	// nodes stores nodes sorted by their name
	nodes []nodeTypes.Node

	// policies stores IEGPs indexed by policyID
	policyCache map[policyID]*Policy

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// cidrConflicts stores all egressCIDRs conflicts, that is,
	// all conflicts that originate from any couple of overlapping CIDRs
	// requested in policies spec.
	// The map key is one of the two conflicting cidrs, and the map value
	// is the other one. Each conflicting CIDR is identified by the policyID
	// where it appears and the CIDR itself.
	cidrConflicts map[policyEgressCIDR]policyEgressCIDR

	// healthchecker checks the health status of the nodes configured as
	// gateway by at least one policy
	healthchecker healthcheck.Healthchecker

	// reconciliationTrigger is the trigger used to reconcile the the egress
	// gateway policies statuses with the list of active and healthy gateway
	// IPs.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger
}

func NewEgressGatewayOperatorManager(p OperatorParams) (out struct {
	cell.Out

	*OperatorManager
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableIPv4EgressGatewayHA {
		return out, nil
	}

	out.OperatorManager = newEgressGatewayOperatorManager(p)

	return out, nil
}

func newEgressGatewayOperatorManager(p OperatorParams) *OperatorManager {
	operatorManager := &OperatorManager{
		clientset:            p.Clientset,
		policies:             p.Policies,
		ciliumNodes:          p.Nodes,
		nodeDataStore:        make(map[string]nodeTypes.Node),
		nodesByIP:            make(map[string]nodeTypes.Node),
		gatewayNodeDataStore: make(map[string]nodeTypes.Node),
		policyConfigs:        make(map[policyID]*PolicyConfig),
		policyCache:          make(map[policyID]*Policy),
		healthchecker:        p.Healthchecker,
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			t, err := trigger.NewTrigger(trigger.Parameters{
				Name:        "egress_gateway_ha_operator_reconciliation",
				MinInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
				TriggerFunc: func(reasons []string) {
					reason := strings.Join(reasons, ", ")
					log.WithField(logfields.Reason, reason).Debug("reconciliation triggered")

					operatorManager.Lock()
					defer operatorManager.Unlock()

					operatorManager.reconcileLocked()
				},
			})
			if err != nil {
				return err
			}

			operatorManager.reconciliationTrigger = t

			go operatorManager.processEvents(ctx)
			operatorManager.startHealthcheckingLoop()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return operatorManager
}

func (operatorManager *OperatorManager) processEvents(ctx context.Context) {
	var policySync, nodeSync bool
	maybeTriggerReconcile := func() {
		if !policySync || !nodeSync {
			return
		}

		operatorManager.Lock()
		defer operatorManager.Unlock()

		if operatorManager.allCachesSynced {
			return
		}

		operatorManager.allCachesSynced = true
		operatorManager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	policyEvents := operatorManager.policies.Events(ctx)
	nodeEvents := operatorManager.ciliumNodes.Events(ctx)

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
				operatorManager.handlePolicyEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				operatorManager.handleNodeEvent(event)
			}
		}
	}
}

// startHealthcheckingLoop spawns a goroutine that periodically checks if the
// health status of any node has changed, and when that's the case, it re runs
// the reconciliation.
func (operatorManager *OperatorManager) startHealthcheckingLoop() {
	go func() {
		for range operatorManager.healthchecker.Events() {
			operatorManager.reconciliationTrigger.TriggerWithReason("healthcheck event")
		}
	}()
}

func (operatorManager *OperatorManager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := operatorManager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		operatorManager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (operatorManager *OperatorManager) onAddEgressPolicy(policy *Policy) error {
	logger := log.WithFields(logrus.Fields{
		logfields.IsovalentEgressGatewayPolicyName: policy.ObjectMeta.Name,
		logfields.K8sUID: policy.ObjectMeta.UID,
	})

	config, err := ParseIEGP(policy)
	if err != nil {
		logger.WithError(err).Warn("Failed to parse IsovalentEgressGatewayPolicy")
		return err
	}

	operatorManager.Lock()
	defer operatorManager.Unlock()

	if _, ok := operatorManager.policyCache[config.id]; !ok {
		logger.Debug("Added IsovalentEgressGatewayPolicy")
	} else {
		logger.Debug("Updated IsovalentEgressGatewayPolicy")
	}

	operatorManager.policyCache[config.id] = policy
	operatorManager.policyConfigs[config.id] = config
	operatorManager.reconciliationTrigger.TriggerWithReason("IsovalentEgressGatewayPolicy added")
	return nil
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (operatorManager *OperatorManager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseIEGPConfigID(policy)

	operatorManager.Lock()
	defer operatorManager.Unlock()

	logger := log.WithField(logfields.IsovalentEgressGatewayPolicyName, configID.Name)

	if operatorManager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete IsovalentEgressGatewayPolicy: policy not found")
		return
	}

	logger.Debug("Deleted IsovalentEgressGatewayPolicy")
	delete(operatorManager.policyCache, configID)
	delete(operatorManager.policyConfigs, configID)

	operatorManager.reconciliationTrigger.TriggerWithReason("IsovalentEgressGatewayPolicy deleted")
}

// handleNodeEvent takes care of node upserts and removals.
func (operatorManager *OperatorManager) handleNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := nodeTypes.ParseCiliumNode(event.Object)

	operatorManager.Lock()
	defer operatorManager.Unlock()

	if event.Kind == resource.Upsert {
		operatorManager.nodeDataStore[node.Name] = node
		operatorManager.onChangeNodeLocked("CiliumNode updated")
	} else {
		delete(operatorManager.nodeDataStore, node.Name)
		operatorManager.onChangeNodeLocked("CiliumNode deleted")
	}
}

func (operatorManager *OperatorManager) onChangeNodeLocked(event string) {
	operatorManager.nodes = []nodeTypes.Node{}
	for _, n := range operatorManager.nodeDataStore {
		operatorManager.nodes = append(operatorManager.nodes, n)
	}
	sort.Slice(operatorManager.nodes, func(i, j int) bool {
		return operatorManager.nodes[i].Name < operatorManager.nodes[j].Name
	})

	operatorManager.nodesByIP = make(map[string]nodeTypes.Node)
	for _, n := range operatorManager.nodeDataStore {
		for _, ipAddress := range n.IPAddresses {
			if ipAddress.AddrType() == addressing.NodeInternalIP {
				operatorManager.nodesByIP[ipAddress.ToString()] = n
			}
		}
	}

	operatorManager.reconciliationTrigger.TriggerWithReason(event)
}

func (operatorManager *OperatorManager) nodeIsHealthy(nodeName string) bool {
	return operatorManager.healthchecker.NodeIsHealthy(nodeName)
}

func (operatorManager *OperatorManager) regenerateGatewayNodesList() {
	nodes := map[string]nodeTypes.Node{}

	for _, policyConfig := range operatorManager.policyConfigs {
		for _, gc := range policyConfig.groupConfigs {
			for _, n := range operatorManager.nodes {
				if gc.selectsNodeAsGateway(n) {
					nodes[n.Name] = n
				}
			}
		}
	}

	operatorManager.gatewayNodeDataStore = nodes
}

func (operatorManager *OperatorManager) updatePolicesGroupStatuses() {
	for _, config := range operatorManager.policyConfigs {
		err := config.updateGroupStatuses(operatorManager)
		if err != nil {
			operatorManager.reconciliationTrigger.TriggerWithReason("retry after error")
		}
	}
}

// policyEgressCIDR uniquely identifies a user specified egress CIDR in a policy
type policyEgressCIDR struct {
	origin policyID
	cidr   netip.Prefix
}

func (pec policyEgressCIDR) String() string {
	return pec.origin.String() + "-" + pec.cidr.String()
}

func (operatorManager *OperatorManager) updateEgressCIDRConflicts() {
	operatorManager.cidrConflicts = make(map[policyEgressCIDR]policyEgressCIDR)

	var egressCIDRs []policyEgressCIDR

	// internal conflicts
	for policyID, policyCfg := range operatorManager.policyConfigs {
		for _, egressCIDR := range policyCfg.egressCIDRs {
			egressCIDRs = append(egressCIDRs, policyEgressCIDR{
				origin: policyID,
				cidr:   egressCIDR,
			})
		}

		if len(policyCfg.egressCIDRs) <= 1 {
			continue
		}

		for i := 0; i < len(policyCfg.egressCIDRs)-1; i++ {
			for j := i + 1; j < len(policyCfg.egressCIDRs); j++ {
				if policyCfg.egressCIDRs[i].Overlaps(policyCfg.egressCIDRs[j]) {
					first, second := policyEgressCIDR{policyID, policyCfg.egressCIDRs[i]}, policyEgressCIDR{policyID, policyCfg.egressCIDRs[j]}
					operatorManager.cidrConflicts[first] = second
					operatorManager.cidrConflicts[second] = first
				}
			}
		}
	}

	if len(egressCIDRs) <= 1 {
		return
	}

	// external conflicts
	for i := 0; i < len(egressCIDRs)-1; i++ {
		// egressCIDR[i] is already conflicting
		if _, found := operatorManager.cidrConflicts[egressCIDRs[i]]; found {
			continue
		}

		for j := i + 1; j < len(egressCIDRs); j++ {
			// egressCIDR[j] is already conflicting
			if _, found := operatorManager.cidrConflicts[egressCIDRs[j]]; found {
				continue
			}

			if egressCIDRs[i].origin == egressCIDRs[j].origin {
				// no need to check CIDRs from the same policy, internal conflicts
				// have already been found
				continue
			}

			if egressCIDRs[i].cidr.Overlaps(egressCIDRs[j].cidr) {
				first, second := policyEgressCIDR{egressCIDRs[i].origin, egressCIDRs[i].cidr}, policyEgressCIDR{egressCIDRs[j].origin, egressCIDRs[j].cidr}

				policy1 := operatorManager.policyConfigs[egressCIDRs[i].origin]
				policy2 := operatorManager.policyConfigs[egressCIDRs[j].origin]

				// mark the most recent policy as conflicting
				if policy1.creationTimestamp.Before(policy2.creationTimestamp) {
					operatorManager.cidrConflicts[second] = first
				} else {
					operatorManager.cidrConflicts[first] = second
				}
			}
		}
	}
}

// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (operatorManager *OperatorManager) reconcileLocked() {
	if !operatorManager.allCachesSynced {
		return
	}

	operatorManager.regenerateGatewayNodesList()
	operatorManager.healthchecker.UpdateNodeList(operatorManager.gatewayNodeDataStore)

	operatorManager.updateEgressCIDRConflicts()
	operatorManager.updatePolicesGroupStatuses()
}

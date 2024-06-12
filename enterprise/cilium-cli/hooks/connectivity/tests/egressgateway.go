// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/wait"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	EgressGroupLabelKey   = "egress-group"
	EgressGroupLabelValue = "test"

	K8sZoneLabel = "topology.kubernetes.io/zone"
)

// bpfEgressGatewayPolicyEntry represents an entry in the BPF egress gateway policy map
type bpfEgressGatewayPolicyEntry struct {
	SourceIP   string
	DestCIDR   string
	EgressIP   string
	GatewayIPs []string
}

// matches is an helper used to compare the receiver bpfEgressGatewayPolicyEntry with another entry
func (e *bpfEgressGatewayPolicyEntry) matches(t bpfEgressGatewayPolicyEntry) bool {
	sort.Strings(t.GatewayIPs)
	sort.Strings(e.GatewayIPs)

	return t.SourceIP == e.SourceIP &&
		t.DestCIDR == e.DestCIDR &&
		t.EgressIP == e.EgressIP &&
		cmp.Equal(t.GatewayIPs, e.GatewayIPs, cmpopts.EquateEmpty())
}

// waitForBpfPolicyEntries waits for the egress gateway policy maps on each node to be populated with the entries
// returned by the targetEntriesCallback
func waitForBpfPolicyEntries(ctx context.Context, t *check.Test,
	targetEntriesCallback func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry,
) {
	ct := t.Context()

	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBpfPolicyEntries := func() error {
		for _, ciliumPod := range ct.CiliumPods() {
			targetEntries := targetEntriesCallback(ciliumPod)

			cmd := strings.Split("cilium bpf egress-ha list -o json", " ")
			stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				t.Fatal("failed to run cilium bpf egress list command: %w", err)
			}

			entries := []bpfEgressGatewayPolicyEntry{}
			json.Unmarshal(stdout.Bytes(), &entries)

		nextTargetEntry:
			for _, targetEntry := range targetEntries {
				for _, entry := range entries {
					if targetEntry.matches(entry) {
						continue nextTargetEntry
					}
				}

				return fmt.Errorf("could not find egress gateway policy entry matching %+v", targetEntry)
			}

		nextEntry:
			for _, entry := range entries {
				for _, targetEntry := range targetEntries {
					if targetEntry.matches(entry) {
						continue nextEntry
					}
				}

				return fmt.Errorf("untracked entry %+v in the egress gateway policy map", entry)
			}
		}

		return nil
	}

	for {
		if err := ensureBpfPolicyEntries(); err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatal("Failed to ensure egress gateway policy map is properly populated:", err)
			}

			continue
		}

		return
	}
}

// waitForAllocatedEgressIP waits for the operator to allocate an egress IP to the gateway node identified by its IP.
// The allocated egress IP is looked for in the policy and egress group specified as input.
func waitForAllocatedEgressIP(ctx context.Context, t *check.Test, policyName string, egressGroup int, gatewayIP string) net.IP {
	ct := t.Context()
	iegpClient := ct.K8sClient().CiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies()

	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureGroupEgressIP := func() (net.IP, error) {
		p, err := iegpClient.Get(ctx, policyName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get policy %s: %w", policyName, err)
		}
		if len(p.Status.GroupStatuses) <= egressGroup {
			return nil, fmt.Errorf("not enough egress group in policy %s, found %d", policyName, len(p.Status.GroupStatuses))
		}
		group := p.Status.GroupStatuses[egressGroup]
		masqueradeIP, found := group.EgressIPByGatewayIP[gatewayIP]
		if !found {
			return nil, fmt.Errorf("no egress ip allocated for gateway node with address %s", gatewayIP)
		}

		return net.ParseIP(masqueradeIP), nil
	}

	for {
		masqueradeIP, err := ensureGroupEgressIP()
		if err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatal("Failed to ensure egress gateway policy map is properly populated:", err)
			}

			continue
		}

		return masqueradeIP
	}
}

// getGatewayNodeInternalIP returns the k8s internal IP of the node acting as gateway for this test
func getGatewayNodeInternalIP(ct *check.ConnectivityTest, egressGatewayNode string) net.IP {
	gatewayNode, ok := ct.Nodes()[egressGatewayNode]
	if !ok {
		return nil
	}

	for _, addr := range gatewayNode.Status.Addresses {
		if addr.Type != v1.NodeInternalIP {
			continue
		}

		ip := net.ParseIP(addr.Address)
		if ip == nil || ip.To4() == nil {
			continue
		}

		return ip
	}

	return nil
}

// splitJSonBlobs takes a string encoding multiple json blobs, for example:
//
//	{
//	"client-ip": "a"
//	}{
//	"client-ip": "b"
//	}
//
// and returns a slice of individual blobls:
//
//	[{"client-ip": "a"}, {"client-ip": "b"}]
func splitJsonBlobs(s string) []string {
	re := regexp.MustCompile("(?s)}.*?{")
	blobs := re.Split(s, -1)

	for i, blob := range blobs {
		blob = strings.TrimSpace(blob)
		if !strings.HasPrefix(blob, "{") {
			blob = "{" + blob
		}
		if !strings.HasSuffix(blob, "}") {
			blob = blob + "}"
		}
		blobs[i] = blob
	}

	return blobs
}

// extractClientIPFromResponses extracts the client IPs from a string containing multiple responses of the echo-external service
func extractClientIPsFromEchoServiceResponses(res string) []net.IP {
	var clientIP struct {
		ClientIP string `json:"client-ip"`
	}

	var clientIPs []net.IP

	blobs := splitJsonBlobs(res)

	for _, blob := range blobs {
		json.Unmarshal([]byte(blob), &clientIP)
		clientIPs = append(clientIPs, net.ParseIP(clientIP.ClientIP).To4())
	}

	return clientIPs
}

// EgressGateway is a test case which, given the iegp-sample-client IsovalentEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - kind-worker2 as gateway node
//
// and the iegp-sample-echo IsovalentEgressGatewayPolicy targeting:
// - tghe echo service pods (kind=echo) as source
// - the 0.0.0.0/0 destination CIDR
// - kind-worker2 as gateway node
//
// tests connectivity for:
// - pod to host traffic
// - pod to service traffic
// - pod to external IP traffic
// - reply traffic for services
// - reply traffic for pods
func EgressGatewayHA() check.Scenario {
	return &egressGatewayHA{}
}

type egressGatewayHA struct{}

func (s *egressGatewayHA) Name() string {
	return "egress-gateway-ha"
}

func (s *egressGatewayHA) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		for _, client := range ct.ClientPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:   client.Pod.Status.PodIP,
					DestCIDR:   "0.0.0.0/0",
					EgressIP:   egressIP,
					GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
				})
		}

		for _, echo := range ct.EchoPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:   echo.Pod.Status.PodIP,
					DestCIDR:   "0.0.0.0/0",
					EgressIP:   egressIP,
					GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
				})
		}

		return targetEntries
	})

	// Ping hosts (pod to host connectivity). Should not get masqueraded with egress IP
	i := 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, dst := range ct.HostNetNSPodsByNode() {
			dst := dst

			t.NewAction(s, fmt.Sprintf("ping-%d", i), &client, &dst, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.PingCommand(dst, features.IPFamilyV4))
			})
			i++
		}
	}

	// DNS query (pod to service connectivity). Should not get masqueraded with egress IP
	i = 0
	for _, client := range ct.ClientPods() {
		client := client

		kubeDNSService, err := ct.K8sClient().GetService(ctx, "kube-system", "kube-dns", metav1.GetOptions{})
		if err != nil {
			t.Fatal("Cannot get kube-dns service")
		}
		kubeDNSServicePeer := check.Service{Service: kubeDNSService}

		t.NewAction(s, fmt.Sprintf("dig-%d", i), &client, kubeDNSServicePeer, features.IPFamilyV4).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.DigCommand(kubeDNSServicePeer, features.IPFamilyV4))
		})
		i++
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service using DNS)
	i = 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4, "-4"))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(egressGatewayNodeInternalIP) {
						t.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service)
	i = 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(egressGatewayNodeInternalIP) {
						t.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}

	// When connecting from outside the cluster to a nodeport service whose pods are selected by an egress policy,
	// the reply traffic should not be SNATed with the egress IP
	i = 0
	for _, client := range ct.ExternalEchoPods() {
		client := client

		for _, node := range ct.Nodes() {
			for _, echo := range ct.EchoServices() {
				// convert the service to a ServiceExternalIP as we want to access it through its external IP
				echo := echo.ToNodeportService(node)

				t.NewAction(s, fmt.Sprintf("curl-echo-service-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, features.IPFamilyV4))
				})
				i++
			}
		}
	}

	if status, ok := ct.Feature(features.Tunnel); ok && !status.Enabled {
		// When connecting from outside the cluster directly to a pod which is selected by an egress policy, the
		// reply traffic should not be SNATed with the egress IP (only connections originating from these pods
		// should go through egress gateway).
		//
		// This test is executed only when Cilium is running in direct routing mode, since we can simply add a
		// route on the node that doesn't run Cilium to direct pod's traffic to the node where the pod is
		// running (while in tunneling mode we would need the external node to send the traffic over the tunnel)
		i = 0
		for _, client := range ct.ExternalEchoPods() {
			client := client

			for _, echo := range ct.EchoPods() {
				t.NewAction(s, fmt.Sprintf("curl-echo-pod-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, features.IPFamilyV4))
				})
				i++
			}
		}
	}
}

// EgressGatewayExcludedCIDRs is a test case which, given the iegp-sample IsovalentEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - the IP of the external node as excluded CIDR
// - kind-worker2 as gateway node
//
// This suite tests the excludedCIDRs property and ensure traffic matching an excluded CIDR does not get masqueraded with the egress IP.
func EgressGatewayExcludedCIDRs() check.Scenario {
	return &egressGatewayExcludedCIDRs{}
}

type egressGatewayExcludedCIDRs struct{}

func (s *egressGatewayExcludedCIDRs) Name() string {
	return "egress-gateway-excluded-cidrs"
}

func (s *egressGatewayExcludedCIDRs) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		for _, client := range ct.ClientPods() {
			for _, nodeWithoutCiliumName := range t.NodesWithoutCilium() {
				nodeWithoutCilium, err := ciliumPod.K8sClient.GetNode(context.Background(), nodeWithoutCiliumName, metav1.GetOptions{})
				if err != nil {
					if k8sErrors.IsNotFound(err) {
						continue
					}

					t.Fatalf("Cannot retrieve external node")
				}

				targetEntries = append(targetEntries,
					bpfEgressGatewayPolicyEntry{
						SourceIP:   client.Pod.Status.PodIP,
						DestCIDR:   "0.0.0.0/0",
						EgressIP:   egressIP,
						GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
					})

				targetEntries = append(targetEntries,
					bpfEgressGatewayPolicyEntry{
						SourceIP:   client.Pod.Status.PodIP,
						DestCIDR:   fmt.Sprintf("%s/32", nodeWithoutCilium.Status.Addresses[0].Address),
						EgressIP:   egressIP,
						GatewayIPs: []string{"Excluded CIDR"},
					})
			}
		}

		return targetEntries
	})

	// Traffic matching an egress gateway policy and an excluded CIDR should leave the cluster masqueraded with the
	// node IP where the pod is running rather than with the egress IP(pod to external service)
	i := 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 10))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(net.ParseIP(client.Pod.Status.HostIP)) {
						t.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}
}

// EgressGatewayMultipleGateways is a test case which, given the iegp-sample IsovalentEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - the IP of the external node as excluded CIDR
// - nodes with the egress-group=test label as gateways (usually kind-control-plane, kind-worker and kind-worker3)
//
// tests that requests from the kind=client pods are redirected to _all_ gateways of the egressGroup
func EgressGatewayMultipleGateways() check.Scenario {
	return &egressGatewayMultipleGateways{}
}

type egressGatewayMultipleGateways struct{}

func (s *egressGatewayMultipleGateways) Name() string {
	return "egress-gateway-multiple-gateway"
}

func (s *egressGatewayMultipleGateways) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	// apply the egress-group=test label to all the nodes running Cilium and build a gatewayNodeName -> egressIP mapping for all such nodes
	gatewayIPsToNames := map[string]string{}
	addNodeLabelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s"}]`, EgressGroupLabelKey, EgressGroupLabelValue)
	for _, node := range ct.Nodes() {
		if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
			continue
		}

		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(addNodeLabelPatch)); err != nil {
			t.Fatalf("cannot add %s=%s label to node %s: %w", EgressGroupLabelKey, EgressGroupLabelValue, node.Name, err)
		}

		gatewayIP := getGatewayNodeInternalIP(ct, node.Name)
		if gatewayIP == nil {
			t.Fatal("Cannot get egress gateway node internal IP")
		}

		gatewayIPsToNames[gatewayIP.String()] = node.Name
	}

	// remove the labels after the test is done
	t.WithFinalizer(func(_ context.Context) error {
		for _, node := range ct.Nodes() {
			removeNodeLabelPatch := fmt.Sprintf(`[{"op":"remove","path":"/metadata/labels/%s"}]`, EgressGroupLabelKey)
			if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
				continue
			}

			if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(removeNodeLabelPatch)); err != nil {
				return fmt.Errorf("cannot remove %s label from node %s: %w", EgressGroupLabelKey, node.Name, err)
			}
		}

		return nil
	})

	// wait for the policy map to be populated
	waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		egressIP := "0.0.0.0"
		egressGatewayNodeInternalIPs := []string{}

		for gatewayIP, nodeName := range gatewayIPsToNames {
			if ciliumPod.Pod.Spec.NodeName == nodeName {
				egressIP = gatewayIP
			}
			egressGatewayNodeInternalIPs = append(egressGatewayNodeInternalIPs, gatewayIP)
		}

		targetEntries := []bpfEgressGatewayPolicyEntry{}

		for _, client := range ct.ClientPods() {
			for _, nodeWithoutCiliumName := range t.NodesWithoutCilium() {
				if _, err := ciliumPod.K8sClient.GetNode(context.Background(), nodeWithoutCiliumName, metav1.GetOptions{}); err != nil {
					if k8sErrors.IsNotFound(err) {
						continue
					}

					t.Fatalf("Cannot retrieve external node: %w", err)
				}

				targetEntries = append(targetEntries, bpfEgressGatewayPolicyEntry{
					SourceIP:   client.Pod.Status.PodIP,
					DestCIDR:   "0.0.0.0/0",
					EgressIP:   egressIP,
					GatewayIPs: egressGatewayNodeInternalIPs,
				})
			}
		}

		return targetEntries
	})

	// run the test
	i := 0
	responsesByClientIP := map[string]int{}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service using DNS)
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100, "-4"))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()]++
				}
			})
			i++
		}
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if _, ok := gatewayIPsToNames[clientIP]; !ok {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways
	for gatewayIP := range gatewayIPsToNames {
		if _, ok := responsesByClientIP[gatewayIP]; !ok {
			t.Fatalf("No request has gone through gateway %s", gatewayIP)
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service)
	i = 0
	responsesByClientIP = map[string]int{}
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()]++
				}
			})
		}
		i++
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if _, ok := gatewayIPsToNames[clientIP]; !ok {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways
	for gatewayIP := range gatewayIPsToNames {
		if _, ok := responsesByClientIP[gatewayIP]; !ok {
			t.Fatalf("No request has gone through gateway %s", gatewayIP)
		}
	}
}

// EgressGatewayAZAffinity is a test case which, given the iegp-sample IsovalentEgressGatewayPolicy targeting:
// - three client pods (kind=client) as source, in 2 different AZ
// - the 0.0.0.0/0 destination CIDR
// - nodes with the egress-group=test label as gateways (usually kind-control-plane, kind-worker and kind-worker3)
//
// tests that requests from the kind=client pods are redirected only to the "local" (i.e. same AZ) gateway as the source pod
func EgressGatewayAZAffinity() check.Scenario {
	return &egressGatewayAZAffinity{}
}

type egressGatewayAZAffinity struct{}

func (s *egressGatewayAZAffinity) Name() string {
	return "egress-gateway-az-affinity"
}

func (s *egressGatewayAZAffinity) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	// apply the AZ label to all nodes
	for nodeName, node := range ct.Nodes() {
		if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
			continue
		}

		addNodeLabelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s"}]`,
			escapePatchString(K8sZoneLabel), fmt.Sprintf("zone-%s", nodeName))
		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(addNodeLabelPatch)); err != nil {
			t.Fatalf("cannot add label to node %s: %s", node.Name, err)
		}

		addNodeLabelPatch = fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s"}]`, EgressGroupLabelKey, EgressGroupLabelValue)
		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(addNodeLabelPatch)); err != nil {
			t.Fatalf("cannot add %s=%s label to node %s: %w", EgressGroupLabelKey, EgressGroupLabelValue, node.Name, err)
		}
	}

	// remove the labels after the test is done
	t.WithFinalizer(func(_ context.Context) error {
		for _, node := range ct.Nodes() {
			if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
				continue
			}

			removeNodeLabelPatch := fmt.Sprintf(`[{"op":"remove","path":"/metadata/labels/%s"}]`, escapePatchString(K8sZoneLabel))
			if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(removeNodeLabelPatch)); err != nil {
				return fmt.Errorf("cannot remove %s label from node %s: %w", EgressGroupLabelKey, node.Name, err)
			}

			removeNodeLabelPatch = fmt.Sprintf(`[{"op":"remove","path":"/metadata/labels/%s"}]`, EgressGroupLabelKey)
			if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(removeNodeLabelPatch)); err != nil {
				return fmt.Errorf("cannot remove %s label from node %s: %w", EgressGroupLabelKey, node.Name, err)
			}
		}

		return nil
	})

	// wait for the policy map to be populated
	waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		for _, client := range ct.ClientPods() {
			egressIP := "0.0.0.0"
			if ciliumPod.Pod.Spec.NodeName == client.Pod.Spec.NodeName {
				egressIP = getGatewayNodeInternalIP(ct, ciliumPod.Pod.Spec.NodeName).String()
			}

			egressGatewayNodeInternalIPs := []string{
				getGatewayNodeInternalIP(ct, client.Pod.Spec.NodeName).String(),
			}

			targetEntries = append(targetEntries, bpfEgressGatewayPolicyEntry{
				SourceIP:   client.Pod.Status.PodIP,
				DestCIDR:   "0.0.0.0/0",
				EgressIP:   egressIP,
				GatewayIPs: egressGatewayNodeInternalIPs,
			})
		}

		return targetEntries
	})

	// run the test
	i := 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(getGatewayNodeInternalIP(ct, client.Pod.Spec.NodeName)) {
						t.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
		}
		i++
	}
}

func escapePatchString(str string) string {
	// From https://www.rfc-editor.org/rfc/rfc6901#section-3:
	// Because the characters '~' (%x7E) and '/' (%x2F) have special meanings in JSON Pointer,
	// '~' needs to be encoded as '~0' and '/' needs to be encoded as '~1' when these characters
	// appear in a reference token.
	str = strings.ReplaceAll(str, "~", "~0")
	str = strings.ReplaceAll(str, "/", "~1")
	return str
}

func EgressGatewayHAIPAM() check.Scenario {
	return &egressGatewayHAIPAM{}
}

type egressGatewayHAIPAM struct{}

func (s *egressGatewayHAIPAM) Name() string {
	return "egress-gateway-ha-ipam"
}

func (s *egressGatewayHAIPAM) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	policyName := "iegp-sample-client"

	masqueradeIP := waitForAllocatedEgressIP(ctx, t, policyName, 0, egressGatewayNodeInternalIP.String())

	waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = masqueradeIP.String()
		}

		for _, client := range ct.ClientPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:   client.Pod.Status.PodIP,
					DestCIDR:   "0.0.0.0/0",
					EgressIP:   egressIP,
					GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
				})
		}

		return targetEntries
	})

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service)
	i := 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(masqueradeIP) {
						t.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}
}

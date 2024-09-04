// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const (
	bfdProfileName      = "test-bfd-profile"
	bfdNodeConfigPrefix = "test-bfd-node-config-"

	frrBFDPeeringTemplate = `
debug bfd peer
bfd
  profile cilium
    receive-interval 150
    transmit-interval 150
    echo receive-interval 100
  exit
{{- range $peer := .Peers }}
  peer {{$peer}} {{if $.MultiHop}}multihop local-address {{$.LocalAddress}}{{end}}
    profile cilium
  exit
{{- end }}
exit
`
)

// frrBFPPeeringParams holds information for rendering FRR BFP peering configuration.
type frrBFPPeeringParams struct {
	Peers        []netip.Addr
	MultiHop     bool
	LocalAddress string
}

// frrBFDPeeringInfo holds FRR BFD peering state information equivalent to "show bfd peers json" CLI output entry.
type frrBFDPeeringInfo struct {
	Peer                      string `json:"peer"`
	Multihop                  bool   `json:"multihop"`
	Id                        int64  `json:"id"`
	RemoteId                  int64  `json:"remote-id"`
	Status                    string `json:"status"`
	Uptime                    int    `json:"uptime"`
	Diagnostic                string `json:"diagnostic"`
	RemoteDiagnostic          string `json:"remote-diagnostic"`
	ReceiveInterval           int    `json:"receive-interval"`
	TransmitInterval          int    `json:"transmit-interval"`
	EchoReceiveInterval       int    `json:"echo-receive-interval"`
	EchoTransmitInterval      int    `json:"echo-transmit-interval"`
	DetectMultiplier          int    `json:"detect-multiplier"`
	RemoteReceiveInterval     int    `json:"remote-receive-interval"`
	RemoteTransmitInterval    int    `json:"remote-transmit-interval"`
	RemoteEchoReceiveInterval int    `json:"remote-echo-receive-interval"`
	RemoteDetectMultiplier    int    `json:"remote-detect-multiplier"`
}

// frrBFDPeeringInfoMap holds BFD peering information keyed by peer IP address.
type frrBFDPeeringInfoMap map[string]*frrBFDPeeringInfo

// BFDStandAloneParams holds BFDStandAlone scenario parameters.
type BFDStandAloneParams struct {
	MultiHop     bool
	EchoFunction bool
}

// BFDStandAlone returns test scenario for BFD standalone functionality (without BGP integration).
func BFDStandAlone(p BFDStandAloneParams) check.Scenario {
	return &bfdStandAlone{
		BFDStandAloneParams: p,
	}
}

type bfdStandAlone struct {
	BFDStandAloneParams
}

func (s *bfdStandAlone) Name() string {
	mode := "control"
	if s.EchoFunction {
		mode = "echo"
	}
	hop := "single"
	if s.MultiHop {
		hop = "multi"
	}
	return "bfd-" + mode + "-" + hop + "-hop"
}

func (s *bfdStandAlone) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	t.ForEachIPFamily(func(ipFamily features.IPFamily) {
		defer func() {
			s.cleanup(ctx, t)
		}()
		s.deleteK8sResources(ctx, t)

		// configure BFD on FRR
		frrPeers := ct.InternalNodeIPAddresses(ipFamily)
		for _, frr := range ct.FRRPods() {
			frrConfig := renderFRRBFDPeeringConfig(t, frrBFPPeeringParams{
				Peers:        frrPeers,
				MultiHop:     s.MultiHop,
				LocalAddress: frr.Address(ipFamily),
			})
			check.ApplyFRRConfig(ctx, t, &frr, frrConfig)
		}

		// configure BFD on Cilium
		bfdProfile := generateBFDProfile(s.MultiHop, s.EchoFunction)
		configureBFDProfile(ctx, t, bfdProfile, false)
		for _, node := range ct.Nodes() {
			configureBFDNodeConfig(ctx, t, node, ipFamily)
		}

		// ensure peering goes Up on both sides
		t.NewGenericAction(s, fmt.Sprintf("ensure-peers-up-%s", ipFamily)).Run(func(a *check.Action) {
			for _, frr := range ct.FRRPods() {
				waitForFRRBFDPeersState(ctx, t, a, &frr, frrPeers, "up")
			}
			for _, ciliumPod := range ct.CiliumPods() {
				waitForCiliumBFDPeersState(ctx, a, &ciliumPod, types.BFDStateUp)
			}
		})

		// test changing timer values
		t.NewGenericAction(s, fmt.Sprintf("frr-timer-change-%s", ipFamily)).Run(func(a *check.Action) {
			uptime := make(map[string]int) // keyed by FRR name + peer IP

			expectedPeerIntervals := func(p *isovalentv1alpha1.IsovalentBFDProfile) *frrBFDPeeringInfo {
				expState := &frrBFDPeeringInfo{
					RemoteReceiveInterval:  int(*p.Spec.ReceiveIntervalMilliseconds),
					RemoteTransmitInterval: int(*p.Spec.TransmitIntervalMilliseconds),
				}
				if s.EchoFunction {
					expState.RemoteReceiveInterval = 1000 // rx interval slows down when the echo function is active
				}
				return expState
			}

			// validate timer values before the change
			for _, frr := range ct.FRRPods() {
				peerInfo := waitForFRRBFDPeersIntervals(ctx, t, a, &frr, expectedPeerIntervals(bfdProfile))
				for _, peer := range peerInfo {
					uptime[frr.Name()+peer.Peer] = peer.Uptime
				}
			}

			// change timer values in BFD profile
			bfdProfile = getBFDProfile(ctx, t)
			bfdProfile.Spec.ReceiveIntervalMilliseconds = ptr.To[int32](160)
			bfdProfile.Spec.TransmitIntervalMilliseconds = ptr.To[int32](160)
			configureBFDProfile(ctx, t, bfdProfile, true)

			// validate timer values after the change
			for _, frr := range ct.FRRPods() {
				peerInfo := waitForFRRBFDPeersIntervals(ctx, t, a, &frr, expectedPeerIntervals(bfdProfile))
				for _, peer := range peerInfo {
					if peer.Uptime < uptime[frr.Name()+peer.Peer] {
						t.Fatalf("FRR %s session flapped (uptime=%d lower than previous=%d)", frr.Name(), peer.Uptime, uptime[frr.Name()+peer.Peer])
					}
				}
			}
		})

		// ensure peering goes Down once BFD is disabled on FRR
		t.NewGenericAction(s, fmt.Sprintf("frr-peer-down-%s", ipFamily)).Run(func(a *check.Action) {
			// disable BFD on FRR
			for _, frr := range ct.FRRPods() {
				frrConfig := renderFRRBFDPeeringConfig(t, frrBFPPeeringParams{})
				check.ApplyFRRConfig(ctx, t, &frr, frrConfig)
			}
			// check peering is Down on Cilium
			for _, ciliumPod := range ct.CiliumPods() {
				waitForCiliumBFDPeersState(ctx, a, &ciliumPod, types.BFDStateDown)
			}
		})
	})
}

func (s *bfdStandAlone) cleanup(ctx context.Context, t *check.Test) {
	if t.Failed() {
		for _, frr := range t.Context().FRRPods() {
			dumpFRRBFDState(ctx, t, &frr)
		}
	}

	// delete test-configured K8s resources
	s.deleteK8sResources(ctx, t)

	// clear FRR config
	for _, frr := range t.Context().FRRPods() {
		check.ClearFRRConfig(ctx, t, &frr)
	}
}

func (s *bfdStandAlone) deleteK8sResources(ctx context.Context, t *check.Test) {
	client := t.Context().K8sClient().CiliumClientset.IsovalentV1alpha1()

	for _, node := range t.Context().Nodes() {
		check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBFDNodeConfigs(), bfdNodeConfigPrefix+node.Name)
	}
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBFDProfiles(), bfdProfileName)
}

// BFDWithBGP returns test scenario for BFD functionality with BGP integration.
func BFDWithBGP() check.Scenario {
	return &bfdWithBGP{}
}

type bfdWithBGP struct{}

func (s *bfdWithBGP) Name() string {
	return "bfd-bgp"
}

func (s *bfdWithBGP) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	t.ForEachIPFamily(func(ipFamily features.IPFamily) {
		defer func() {
			s.cleanup(ctx, t)
		}()

		// configure FRR
		frrPeers := ct.InternalNodeIPAddresses(ipFamily)
		bgpFRRConfig := check.RenderFRRBGPPeeringConfig(t, check.FRRBGPPeeringParams{
			LocalASN: bgpFRRASN,
			Peers:    frrPeers,
		})
		bfdFRRConfig := renderFRRBFDPeeringConfig(t, frrBFPPeeringParams{
			Peers: frrPeers,
		})
		for _, frr := range ct.FRRPods() {
			check.ApplyFRRConfig(ctx, t, &frr, bgpFRRConfig+bfdFRRConfig)
		}

		// configure BGP + BFD on Cilium
		configureBGPPeering(ctx, t, ipFamily, bfdProfileName)
		bfdProfile := generateBFDProfile(false, false)
		configureBFDProfile(ctx, t, bfdProfile, false)

		// ensure BGP peering is established
		t.NewGenericAction(s, fmt.Sprintf("ensure-bgp-established-%s", ipFamily)).Run(func(a *check.Action) {
			for _, frr := range ct.FRRPods() {
				check.WaitForFRRBGPNeighborsState(ctx, t, &frr, frrPeers, "Established")
			}
		})

		// ensure BFD peering goes Up on both sides
		t.NewGenericAction(s, fmt.Sprintf("ensure-bfd-up-%s", ipFamily)).Run(func(a *check.Action) {
			for _, frr := range ct.FRRPods() {
				waitForFRRBFDPeersState(ctx, t, a, &frr, frrPeers, "up")
			}
			for _, ciliumPod := range ct.CiliumPods() {
				waitForCiliumBFDPeersState(ctx, a, &ciliumPod, types.BFDStateUp)
			}
		})
	})
}

func (s *bfdWithBGP) cleanup(ctx context.Context, t *check.Test) {
	if t.Failed() {
		for _, frr := range t.Context().FRRPods() {
			dumpFRRBFDState(ctx, t, &frr)
			check.DumpFRRBGPState(ctx, t, &frr)
		}
	}

	// delete test-configured K8s resources
	s.deleteK8sResources(ctx, t)

	// clear FRR config
	for _, frr := range t.Context().FRRPods() {
		check.ClearFRRConfig(ctx, t, &frr)
	}
}

func (s *bfdWithBGP) deleteK8sResources(ctx context.Context, t *check.Test) {
	client := t.Context().K8sClient().CiliumClientset.IsovalentV1alpha1()

	deleteBGPPeeringResources(ctx, t)

	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBFDProfiles(), bfdProfileName)
}

func generateBFDProfile(multiHop, echoFunction bool) *isovalentv1alpha1.IsovalentBFDProfile {
	profile := &isovalentv1alpha1.IsovalentBFDProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: bfdProfileName,
		},
		Spec: isovalentv1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](150),
			TransmitIntervalMilliseconds: ptr.To[int32](150),
			DetectMultiplier:             ptr.To[int32](3),
		},
	}
	if multiHop {
		profile.Spec.MinimumTTL = ptr.To[int32](254)
	}
	if echoFunction {
		profile.Spec.EchoFunction = &isovalentv1alpha1.BFDEchoFunctionConfig{
			ReceiveIntervalMilliseconds:  ptr.To[int32](100),
			TransmitIntervalMilliseconds: ptr.To[int32](100),
			Directions: []isovalentv1alpha1.BFDEchoFunctionDirection{
				isovalentv1alpha1.BFDEchoFunctionDirectionTransmit,
				// transmit only, as FRR does not support Echo Function transit to non-FRR peers
			},
		}
	}
	return profile
}

func configureBFDProfile(ctx context.Context, t *check.Test, profile *isovalentv1alpha1.IsovalentBFDProfile, isUpdate bool) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.IsovalentV1alpha1()

	if isUpdate {
		_, err := client.IsovalentBFDProfiles().Update(ctx, profile, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("failed to update IsovalentBFDProfile: %v", err)
		}
	} else {
		_, err := client.IsovalentBFDProfiles().Create(ctx, profile, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("failed to create IsovalentBFDProfile: %v", err)
		}
	}
}

func getBFDProfile(ctx context.Context, t *check.Test) *isovalentv1alpha1.IsovalentBFDProfile {
	profile, err := t.Context().K8sClient().CiliumClientset.IsovalentV1alpha1().IsovalentBFDProfiles().
		Get(ctx, bfdProfileName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get IsovalentBFDProfile: %v", err)
	}
	return profile
}

func configureBFDNodeConfig(ctx context.Context, t *check.Test, node *corev1.Node, ipFamily features.IPFamily) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.IsovalentV1alpha1()

	nc := &isovalentv1alpha1.IsovalentBFDNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bfdNodeConfigPrefix + node.Name,
		},
		Spec: isovalentv1alpha1.BFDNodeConfigSpec{
			NodeRef: node.Name,
		},
	}
	for _, frr := range ct.FRRPods() {
		nc.Spec.Peers = append(nc.Spec.Peers, &isovalentv1alpha1.BFDNodePeerConfig{
			Name:          "test-peer-" + frr.Address(ipFamily),
			PeerAddress:   frr.Address(ipFamily),
			BFDProfileRef: bfdProfileName,
		})
	}
	_, err := client.IsovalentBFDNodeConfigs().Create(ctx, nc, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBFDNodeConfig: %v", err)
	}
}

// renderFRRBFDPeeringConfig renders standard BFD peering configuration for provided parameters.
// The returned config can be used to apply in an FRR pod.
func renderFRRBFDPeeringConfig(t *check.Test, params frrBFPPeeringParams) string {
	var config bytes.Buffer
	tpl, err := template.New("").Parse(frrBFDPeeringTemplate)
	if err != nil {
		t.Fatalf("failed to parse FRR config template: %v", err)
	}
	err = tpl.Execute(&config, params)
	if err != nil {
		t.Fatalf("failed to render FRR config template: %v", err)
	}
	return config.String()
}

// waitForFRRBFDPeersState waits until provided list of BFD peers reach the provided state
// on the provided FRR pod.
func waitForFRRBFDPeersState(ctx context.Context, t *check.Test, a *check.Action, frrPod *check.Pod, expPeers []netip.Addr, expState string) frrBFDPeeringInfoMap {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBFDPeersState := func() (frrBFDPeeringInfoMap, error) {
		frrPeers, err := getFRRBFDPeers(ctx, t, frrPod)
		if err != nil {
			return nil, err
		}
		for _, peer := range expPeers {
			frrPeer, exists := frrPeers[peer.String()]
			if !exists {
				return nil, fmt.Errorf("missing peer %s", peer.String())
			}
			if frrPeer.Status != expState {
				return nil, fmt.Errorf("peer %s: expected %s state, got %s", peer, expState, frrPeer.Status)
			}
		}
		return frrPeers, nil
	}

	for {
		peers, err := ensureBFDPeersState()
		if err != nil {
			if retErr := w.Retry(err); retErr != nil {
				a.Fatalf("Failed to ensure FRR BFD peer state: %v", retErr)
			}
			continue
		}
		return peers
	}
}

// waitForFRRBFDPeersIntervals waits until all BFD peers match the timer intervals
// provided in the expectedPeer argument on the provided FRR pod.
func waitForFRRBFDPeersIntervals(ctx context.Context, t *check.Test, a *check.Action, frrPod *check.Pod, expectedPeer *frrBFDPeeringInfo) frrBFDPeeringInfoMap {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBFDPeersIntervals := func() (frrBFDPeeringInfoMap, error) {
		frrPeers, err := getFRRBFDPeers(ctx, t, frrPod)
		if err != nil {
			return nil, err
		}
		for _, peer := range frrPeers {
			if peer.RemoteReceiveInterval != expectedPeer.RemoteReceiveInterval || peer.RemoteTransmitInterval != expectedPeer.RemoteTransmitInterval {
				return nil, fmt.Errorf("remote rx/tx intervals (rx=%d/tx=%d) do not match expected values (rx=%d/tx=%d)",
					peer.RemoteReceiveInterval, peer.RemoteTransmitInterval, expectedPeer.RemoteReceiveInterval, expectedPeer.RemoteTransmitInterval)
			}
		}
		return frrPeers, nil
	}

	for {
		peer, err := ensureBFDPeersIntervals()
		if err != nil {
			if retErr := w.Retry(err); retErr != nil {
				a.Fatalf("Failed to ensure FRR BFD peer intervals: %v", retErr)
			}
			continue
		}
		return peer
	}
}

// getFRRBFDPeers returns BFD peers configured on the provided FRR pod.
func getFRRBFDPeers(ctx context.Context, t *check.Test, frrPod *check.Pod) (frrBFDPeeringInfoMap, error) {
	stdout := check.RunFRRCommand(ctx, t, frrPod, "show bfd peers json")
	var frrPeersArr []frrBFDPeeringInfo
	err := json.Unmarshal(stdout, &frrPeersArr)
	if err != nil {
		return nil, err
	}
	frrPeers := make(frrBFDPeeringInfoMap)
	for _, p := range frrPeersArr {
		frrPeers[p.Peer] = &p
	}
	return frrPeers, nil
}

// waitForCiliumBFDPeersState waits until all BFD peers on provided cilium pod reach the provided state.
func waitForCiliumBFDPeersState(ctx context.Context, a *check.Action, ciliumPod *check.Pod, expState types.BFDState) []types.BFDPeerStatus {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBFDPeersState := func() ([]types.BFDPeerStatus, error) {
		// TODO: replace with "cilium-dbg statedb bfd-peers -o json" once supported
		cmd := strings.Split("cilium-dbg statedb dump", " ")
		stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			a.Fatalf("failed to run cilium-dbg command: %v", err)
		}

		stateDBInfo := struct {
			BFDPeers []types.BFDPeerStatus `json:"bfd-peers"`
		}{}
		err = json.Unmarshal(stdout.Bytes(), &stateDBInfo)
		if err != nil {
			a.Fatalf("failed to unmarshall statdeb info: %v", err)
		}

		for _, peer := range stateDBInfo.BFDPeers {
			if peer.Local.State != expState {
				return nil, fmt.Errorf("peer %s: expected %s state, got %s", peer.PeerAddress, expState, peer.Local.State)
			}
		}
		return stateDBInfo.BFDPeers, nil
	}

	for {
		peers, err := ensureBFDPeersState()
		if err != nil {
			if retErr := w.Retry(err); retErr != nil {
				a.Fatalf("Failed to ensure Cilium BFD peer state: %v", retErr)
			}
			continue
		}
		return peers
	}
}

// dumpFRRBFDState dumps FRR's BFD state into the log.
func dumpFRRBFDState(ctx context.Context, t *check.Test, frrPod *check.Pod) {
	t.Logf("FRR %s state:", frrPod.Name())
	t.Logf("%s", check.RunFRRCommand(ctx, t, frrPod, "show bfd peers"))
}

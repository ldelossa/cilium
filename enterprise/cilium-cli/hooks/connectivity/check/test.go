//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package check

import (
	"context"
	_ "embed"
	"fmt"
	"net"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	enterpriseTests "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/tests"
	enterpriseFeatures "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/utils/features"
)

//go:embed manifests/egress-gateway-policy.yaml
var egressGatewayPolicyYAML string

//go:embed manifests/multicast-group.yaml
var multicastGroupYAML string

type EnterpriseTest struct {
	*check.Test

	ctx *EnterpriseConnectivityTest

	// Isovalent Egress Gateway Policies active during this test.
	iegps map[string]*isovalentv1.IsovalentEgressGatewayPolicy

	// Isovalent Multicast Groups active during this test.
	imgs map[string]*isovalentv1alpha1.IsovalentMulticastGroup

	// multicast deployments active during this test
	mcastDeploys map[string]*appsv1.Deployment
}

func (t *EnterpriseTest) Context() *EnterpriseConnectivityTest {
	return t.ctx
}

type EgressGroupKind int

const (
	// SingleGateway configures the egressGroup of the policy with a single gateway node, the one returned by (*Test)EgressGatewayNode().
	// Currently the designated node is the one running the other=client client pod
	SingleGateway EgressGroupKind = iota

	// AllCiliumNodes configures the egressGroup of the policy with all nodes running Cilium as gateway nodes
	AllCiliumNodes
)

type ExcludedCIDRsKind int

const (
	// NoExcludedCIDRs does not configure any excluded CIDRs in the policy
	NoExcludedCIDRs ExcludedCIDRsKind = iota

	// ExternalNodeExcludedCIDRs adds the IPs of the external nodes (i.e the ones with the "cilium.io/no-schedule" label) to the list of excluded CIDRs
	ExternalNodeExcludedCIDRs
)

// IsovalentEgressGatewayPolicyParams is used to configure how an IsovalentEgressGatewayPolicy template should be
// configured before being applied.
type IsovalentEgressGatewayPolicyParams struct {
	// Name controls the name of the policy
	Name string

	// PodSelectorKind is used to select the client pods. The parameter is used to select pods with a matching "kind" label
	PodSelectorKind string

	// EgressCIDRs is the list of CIDRs used to allocate egress IPs for the policy
	EgressCIDRs []string

	// EgressGroup controls how the egressGroup of the policy should be configured
	EgressGroup EgressGroupKind

	// ExcludedCIDRs controls how the ExcludedCIDRs property should be configured
	ExcludedCIDRs ExcludedCIDRsKind

	// AZAffinity controls the azAffinity property
	AZAffinity string
}

// WithIsovalentEgressGatewayPolicy takes a string containing a YAML policy
// document and adds the cilium egress gateway polic(y)(ies) to the scope of the
// Test, to be applied when the test starts running. When calling this method,
// note that the egress gateway enabled feature requirement is applied directly
// here.
func (t *EnterpriseTest) WithIsovalentEgressGatewayPolicy(params IsovalentEgressGatewayPolicyParams) *EnterpriseTest {
	pl, err := check.ParsePolicyYAML[*isovalentv1.IsovalentEgressGatewayPolicy](egressGatewayPolicyYAML, scheme.Scheme)
	if err != nil {
		t.Fatalf("Parsing policy YAML: %s", err)
	}

	for i := range pl {
		// Change the default test namespace as required.
		for _, k := range []string{
			k8sConst.PodNamespaceLabel,
			check.KubernetesSourcedLabelPrefix + k8sConst.PodNamespaceLabel,
			check.AnySourceLabelPrefix + k8sConst.PodNamespaceLabel,
		} {
			for _, e := range pl[i].Spec.Selectors {
				ps := e.PodSelector
				if n, ok := ps.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
					ps.MatchLabels[k] = t.Test.Context().Params().TestNamespace
				}
			}
		}

		// Set the policy name
		pl[i].Name = params.Name

		// Set the pod selector
		pl[i].Spec.Selectors[0].PodSelector.MatchLabels["kind"] = params.PodSelectorKind

		// Set the egress group
		var (
			egressGroupKey   = ""
			egressGroupValue = ""
		)

		switch params.EgressGroup {
		case SingleGateway:
			egressGatewayNodeName := t.EgressGatewayNode()
			if egressGatewayNodeName == "" {
				t.Fatalf("Cannot find egress gateway node")
			}

			egressGroupKey = "kubernetes.io/hostname"
			egressGroupValue = egressGatewayNodeName
		case AllCiliumNodes:
			egressGroupKey = enterpriseTests.EgressGroupLabelKey
			egressGroupValue = enterpriseTests.EgressGroupLabelValue
		}

		eg := []isovalentv1.EgressGroup{
			{
				NodeSelector: &slimv1.LabelSelector{
					MatchLabels: map[string]slimv1.MatchLabelsValue{
						egressGroupKey: egressGroupValue,
					},
				},
			},
		}
		pl[i].Spec.EgressGroups = eg

		// Set the excluded CIDRs
		pl[i].Spec.ExcludedCIDRs = []isovalentv1.IPv4CIDR{}

		switch params.ExcludedCIDRs {
		case ExternalNodeExcludedCIDRs:
			for _, nodeWithoutCiliumIP := range t.Context().Params().NodesWithoutCiliumIPs {
				if parsedIP := net.ParseIP(nodeWithoutCiliumIP.IP); parsedIP.To4() == nil {
					continue
				}

				cidr := isovalentv1.IPv4CIDR(fmt.Sprintf("%s/32", nodeWithoutCiliumIP.IP))
				pl[i].Spec.ExcludedCIDRs = append(pl[i].Spec.ExcludedCIDRs, cidr)
			}
		}

		egressCIDRs := make([]isovalentv1.IPv4CIDR, 0, len(params.EgressCIDRs))
		for _, cidr := range params.EgressCIDRs {
			egressCIDRs = append(egressCIDRs, isovalentv1.IPv4CIDR(cidr))
		}
		pl[i].Spec.EgressCIDRs = egressCIDRs

		if params.AZAffinity == "" {
			params.AZAffinity = "disabled"
		}
		pl[i].Spec.AZAffinity = params.AZAffinity
	}

	if err := t.addIEGPs(pl...); err != nil {
		t.Fatalf("Adding IEGPs to cilium egress gateway policy context: %s", err)
	}

	t.WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.EgressGatewayHA))

	return t
}

type IsovalentMulticastGroupParams struct {
	Name            string
	GroupAddrPrefix string
	Groups          int
}

// WithIsovalentMulticastGroup takes a string containing a YAML policy
// document and adds the isovalent multicast group(s) to the scope of the
// Test, to be applied when the test starts running. When calling this method,
// note that the multicast enabled feature requirement is applied directly
// here.
func (t *EnterpriseTest) WithIsovalentMulticastGroup(params IsovalentMulticastGroupParams) *EnterpriseTest {
	pl, err := check.ParsePolicyYAML[*isovalentv1alpha1.IsovalentMulticastGroup](multicastGroupYAML, scheme.Scheme)
	if err != nil {
		t.Fatalf("Parsing policy YAML: %s", err)
	}

	for i := range pl {
		// Set the policy name
		pl[i].Name = params.Name

		// Set the groups
		pl[i].Spec.GroupAddrs = enterpriseTests.GenerateMulticastGroups(params.GroupAddrPrefix, params.Groups)
	}

	if err := t.addIMGs(pl...); err != nil {
		t.Fatalf("Adding IMGs to multicast group context: %s", err)
	}

	t.WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.Multicast))
	return t
}

type MulticastDeploymentParams struct {
	Name        string
	Labels      map[string]string
	IGMPVersion int
}

func (t *EnterpriseTest) WithMulticastDeployment(params MulticastDeploymentParams) *EnterpriseTest {
	readinessProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				// we only need to run socat/ip route commands inside the container to check if the multicast is working
				// checking if the ip route command is working is enough
				Command: []string{"ip", "route"},
			},
		},
		PeriodSeconds:       int32(3),
		InitialDelaySeconds: int32(1),
		FailureThreshold:    int32(20),
	}
	deployParams := deploymentParameters{
		Name:     params.Name,
		Kind:     kindMulticastName,
		Image:    "nicolaka/netshoot:v0.12",
		Replicas: 2,
		Port:     8000,
		Command:  []string{"sleep", "infinite"},
		Affinity: &corev1.Affinity{
			// do not schedule the pods on the same node
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: params.Labels,
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		},
		Labels:                        params.Labels,
		ReadinessProbe:                readinessProbe,
		TerminationGracePeriodSeconds: ptr.To[int64](1),
	}

	dep := newMulticastDeployment(deployParams, params.IGMPVersion)

	if err := t.addMulticastDeployment(dep); err != nil {
		t.Fatalf("Adding multicast deployment to cilium context: %s", err)
	}

	t.WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.Multicast))
	return t
}

func (t *EnterpriseTest) WithScenarios(sl ...check.Scenario) *EnterpriseTest {
	t.Test.WithScenarios(sl...)

	return t
}

func (t *EnterpriseTest) setup(ctx context.Context) error {
	if err := t.applyPolicies(ctx); err != nil {
		t.CiliumLogs(ctx)
		return fmt.Errorf("applying policies: %w", err)
	}

	if err := t.applyDeployments(ctx); err != nil {
		t.CiliumLogs(ctx)
		return fmt.Errorf("applying deployments: %w", err)
	}

	return nil
}

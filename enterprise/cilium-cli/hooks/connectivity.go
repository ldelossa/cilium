//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package hooks

import (
	_ "embed"
	"fmt"

	"github.com/blang/semver/v4"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"

	enterpriseCheck "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/check"
	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/deploy"
	enterpriseTests "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/tests"
	enterpriseFeatures "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/utils/features"
)

const (
	testNoPolicies = "no-policies"
)

//go:embed manifests/allow-all-dns-loookups-policy.yaml
var allowAllDNSLookupsPolicyYAML string

//go:embed manifests/client-egress-icmp.yaml
var clientEgressICMPYAML string

//go:embed manifests/client-egress-l7-http-external-node.yaml
var clientEgressL7HTTPAnywhereYAML string

//go:embed manifests/client-egress-only-dns.yaml
var clientEgressOnlyDNSPolicyYAML string

type EnterpriseConnectivity struct {
	externalCiliumDNSProxyPods map[string]check.Pod
	mixedRoutingScenario       check.Scenario
}

func (ec *EnterpriseConnectivity) addConnectivityTests(ct *check.ConnectivityTest) error {
	if err := ec.addHubbleVersionTests(ct); err != nil {
		return err
	}

	if err := ec.addExternalCiliumDNSProxyTests(ct); err != nil {
		return err
	}

	if err := ec.addPhantomServiceTests(ct); err != nil {
		return err
	}

	if ct.Params().IncludeUnsafeTests {
		if err := ec.addEgressGatewayHATests(ct); err != nil {
			return err
		}
	}

	if err := ec.addMulticastTests(ct); err != nil {
		return err
	}

	// Always keep the mixed routing mode tests last, as they assert that the
	// correct routing mode was used to forward the packets generated by all
	// the other tests.
	if err := ec.addMixedRoutingTests(ct); err != nil {
		return err
	}

	return nil
}

func (ec *EnterpriseConnectivity) addHubbleVersionTests(ct *check.ConnectivityTest) error {
	test, err := ct.GetTest(testNoPolicies)
	if err != nil {
		return fmt.Errorf("failed to get test %s: %w", testNoPolicies, err)
	}
	test.WithScenarios(enterpriseTests.HubbleCLIVersion())
	return nil
}

func (ec *EnterpriseConnectivity) addExternalCiliumDNSProxyTests(ct *check.ConnectivityTest) error {
	test := check.NewTest("cilium-dns-proxy-ha", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test).WithCiliumPolicy(allowAllDNSLookupsPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.CiliumDNSProxyHA)).
		WithScenarios(enterpriseTests.ExternalCiliumDNSProxy(ec.externalCiliumDNSProxyPods)).WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
		return check.ResultOK.ExpectMetricsIncrease(enterpriseTests.ExternalCiliumDNSProxySource(ec.externalCiliumDNSProxyPods), "isovalent_external_dns_proxy_policy_l7_total"),
			check.ResultNone
	})
	return nil
}

func (ec *EnterpriseConnectivity) addPhantomServiceTests(ct *check.ConnectivityTest) (err error) {
	// Phantom service support has been introduced in Isovalent Enterprise for Cilium v1.13.2
	if ct.Params().MultiCluster == "" || ct.CiliumVersion.LT(semver.MustParse("1.13.2")) {
		return nil
	}

	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	ct.MustGetTest("no-policies").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	ct.MustGetTest("allow-all-except-world").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())

	// Traffic shall be dropped, because it is subject to the ingress/egress policy.
	ct.MustGetTest("all-ingress-deny").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	ct.MustGetTest("all-ingress-deny-knp").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	ct.MustGetTest("all-egress-deny").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	ct.MustGetTest("all-egress-deny-knp").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	ct.MustGetTest("cluster-entity-multi-cluster").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())

	// Traffic shall be allowed, because it matches the cross-cluster policy.
	ct.MustGetTest("client-egress").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	ct.MustGetTest("client-egress-knp").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())

	return
}

func (ec *EnterpriseConnectivity) addEgressGatewayHATests(ct *check.ConnectivityTest) (err error) {
	newTest := func(ct *check.ConnectivityTest, name string) *enterpriseCheck.EnterpriseTest {
		return enterpriseCheck.NewEnterpriseConnectivityTest(ct).
			NewEnterpriseTest(name).
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.EgressGatewayHA),
				features.RequireEnabled(features.NodeWithoutCilium))
	}

	newTest(ct, "egress-gateway-ha").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.SingleGateway,
		}).
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-echo",
			PodSelectorKind: "echo",
			EgressGroup:     enterpriseCheck.SingleGateway,
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(enterpriseTests.EgressGatewayHA())

	if versioncheck.MustCompile(">=1.16.0")(ct.CiliumVersion) {
		newTest(ct, "egress-gateway-ha-with-l7-policy").
			WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
				Name:            "iegp-sample-client",
				PodSelectorKind: "client",
				EgressGroup:     enterpriseCheck.SingleGateway,
			}).
			WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
				Name:            "iegp-sample-echo",
				PodSelectorKind: "echo",
				EgressGroup:     enterpriseCheck.SingleGateway,
			}).
			WithCiliumPolicy(clientEgressICMPYAML).
			WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).  // DNS resolution only
			WithCiliumPolicy(clientEgressL7HTTPAnywhereYAML). // L7 allow policy with HTTP introspection
			WithIPRoutesFromOutsideToPodCIDRs().
			WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
			WithScenarios(enterpriseTests.EgressGatewayHA())
	}

	newTest(ct, "egress-gateway-ha-excluded-cidrs").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.SingleGateway,
			ExcludedCIDRs:   enterpriseCheck.ExternalNodeExcludedCIDRs,
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(enterpriseTests.EgressGatewayExcludedCIDRs())

	newTest(ct, "egress-gateway-ha-multiple-gateways").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.AllCiliumNodes,
		}).
		WithScenarios(enterpriseTests.EgressGatewayMultipleGateways())

	if versioncheck.MustCompile(">=1.16.0")(ct.CiliumVersion) {
		newTest(ct, "egress-gateway-ha-multiple-gateways-with-l7-policy").
			WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
				Name:            "iegp-sample-client",
				PodSelectorKind: "client",
				EgressGroup:     enterpriseCheck.AllCiliumNodes,
			}).
			WithCiliumPolicy(clientEgressICMPYAML).
			WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).  // DNS resolution only
			WithCiliumPolicy(clientEgressL7HTTPAnywhereYAML). // L7 allow policy with HTTP introspection
			WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
			WithScenarios(enterpriseTests.EgressGatewayMultipleGateways())
	}

	if versioncheck.MustCompile(">=1.14.8")(ct.CiliumVersion) {
		newTest(ct, "egress-gateway-ha-az-affinity").
			WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
				Name:            "iegp-sample-client",
				PodSelectorKind: "client",
				EgressGroup:     enterpriseCheck.AllCiliumNodes,
				// we are only e2e testing the localOnly mode for now.
				// Other configurations are already thoroughly tested in unit tests and would require additional nodes
				AZAffinity: "localOnly",
			}).
			WithScenarios(enterpriseTests.EgressGatewayAZAffinity())
	}

	return nil
}

func (ec *EnterpriseConnectivity) addMixedRoutingTests(ct *check.ConnectivityTest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	// Encryption related tests cannot be run (neither in sanity nor assert mode) if
	// the two clusters are configured with different routing modes, because the
	// tcpdump filters to assert no unencrypted packet is leaked would be incorrect.
	ct.MustGetTest("pod-to-pod-encryption").WithFeatureRequirements(features.RequireDisabled(enterpriseFeatures.MixedRoutingMode))
	ct.MustGetTest("node-to-node-encryption").WithFeatureRequirements(features.RequireDisabled(enterpriseFeatures.MixedRoutingMode))

	// Requirements changes should be additionally applied to the ones guarding
	// the execution of the associated setup function, so that they always match.
	if ct.Params().IncludeUnsafeTests {
		// Generate extra traffic from one pod in each cluster to each Cilium
		// HealthIP, to prevent the sanity checks from reporting false positives
		// due to the lack of other traffic flowing in the cluster. The already
		// existing health check test is not sufficient when WireGuard is enabled,
		// because node to pod traffic is not encrypted by default.
		ct.AddTest(check.NewTest("mixed-routing-extra-traffic", ct.Params().Verbose, ct.Params().Debug)).
			WithFeatureRequirements(
				features.RequireEnabled(features.HealthChecking),
				features.RequireEnabled(enterpriseFeatures.FallbackRoutingMode),
			).
			WithScenarios(enterpriseTests.MixedRoutingExtraTraffic())

		ct.AddTest(check.NewTest("mixed-routing", ct.Params().Verbose, ct.Params().Debug)).
			WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.FallbackRoutingMode)).
			WithSysdumpPolicy(check.SysdumpPolicyNever).
			WithScenarios(ec.mixedRoutingScenario)
	}

	return nil
}

func (ec *EnterpriseConnectivity) addMulticastTests(ct *check.ConnectivityTest) (err error) {
	newTest := func(ct *check.ConnectivityTest, name string) *enterpriseCheck.EnterpriseTest {
		return enterpriseCheck.NewEnterpriseConnectivityTest(ct).
			NewEnterpriseTest(name).
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.Multicast),
			)
	}

	// test igmp v2
	igmpv2Test := newTest(ct, "multicast-igmpv2-check").
		WithMulticastDeployment(enterpriseCheck.MulticastDeploymentParams{
			Name: "multicast-source-v2",
			Labels: map[string]string{
				enterpriseTests.MulticastLabelKey: enterpriseTests.SourceLabel,
			},
		}).
		WithMulticastDeployment(enterpriseCheck.MulticastDeploymentParams{
			Name: "multicast-subscriber-v2",
			Labels: map[string]string{
				enterpriseTests.MulticastLabelKey: enterpriseTests.SubscriberLabel,
			},
			IGMPVersion: 2,
		}).
		WithIsovalentMulticastGroup(
			enterpriseCheck.IsovalentMulticastGroupParams{
				Name:            "igmpv2-version-test",
				GroupAddrPrefix: "226.1.0.0",
				Groups:          5,
			})
	igmpv2Test.WithScenarios(enterpriseTests.MulticastGroupCheck(igmpv2Test.Context().EntClients()))

	// test igmp v3 group check
	igmpv3Test := newTest(ct, "multicast-igmpv3-check").
		WithMulticastDeployment(enterpriseCheck.MulticastDeploymentParams{
			Name: "multicast-source-v3",
			Labels: map[string]string{
				enterpriseTests.MulticastLabelKey: enterpriseTests.SourceLabel,
			},
		}).
		WithMulticastDeployment(enterpriseCheck.MulticastDeploymentParams{
			Name: "multicast-subscriber-v3",
			Labels: map[string]string{
				enterpriseTests.MulticastLabelKey: enterpriseTests.SubscriberLabel,
			},
			IGMPVersion: 3,
		}).
		WithIsovalentMulticastGroup(
			enterpriseCheck.IsovalentMulticastGroupParams{
				Name:            "igmpv3-version-test",
				GroupAddrPrefix: "226.2.0.0",
				Groups:          5,
			})
	igmpv3Test.WithScenarios(enterpriseTests.MulticastGroupCheck(igmpv3Test.Context().EntClients()))

	// check multicast connectivity
	mcastConnectivityTest := newTest(ct, "multicast-connectivity").
		WithMulticastDeployment(enterpriseCheck.MulticastDeploymentParams{
			Name: "multicast-source-conn",
			Labels: map[string]string{
				enterpriseTests.MulticastLabelKey: enterpriseTests.SourceLabel,
			},
		}).
		WithMulticastDeployment(enterpriseCheck.MulticastDeploymentParams{
			Name: "multicast-subscriber-conn",
			Labels: map[string]string{
				enterpriseTests.MulticastLabelKey: enterpriseTests.SubscriberLabel,
			},
			IGMPVersion: 3,
		}).
		WithIsovalentMulticastGroup(
			enterpriseCheck.IsovalentMulticastGroupParams{
				Name:            "conn-test",
				GroupAddrPrefix: "226.4.0.0",
				Groups:          5,
			})
	mcastConnectivityTest.WithScenarios(enterpriseTests.MulticastConnectivity(mcastConnectivityTest.Context().EntClients(), 100))

	return nil
}

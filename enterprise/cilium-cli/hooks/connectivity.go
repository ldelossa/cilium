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

func addConnectivityTests(ct *check.ConnectivityTest, externalCiliumDNSProxyPods map[string]check.Pod) error {
	if err := addHubbleVersionTests(ct); err != nil {
		return err
	}

	if err := addExternalCiliumDNSProxyTests(ct, externalCiliumDNSProxyPods); err != nil {
		return err
	}

	if err := addPhantomServiceTests(ct); err != nil {
		return err
	}

	if ct.Params().IncludeUnsafeTests {
		if err := addEgressGatewayHATests(ct); err != nil {
			return err
		}
	}

	return nil
}

func addHubbleVersionTests(ct *check.ConnectivityTest) error {
	test, err := ct.GetTest(testNoPolicies)
	if err != nil {
		return fmt.Errorf("failed to get test %s: %w", testNoPolicies, err)
	}
	test.WithScenarios(enterpriseTests.HubbleCLIVersion())
	return nil
}

func addExternalCiliumDNSProxyTests(ct *check.ConnectivityTest, pods map[string]check.Pod) error {
	ct.NewTest("external-cilium-dns-proxy").WithCiliumPolicy(allowAllDNSLookupsPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.CiliumDNSProxyDeployed)).
		WithScenarios(enterpriseTests.ExternalCiliumDNSProxy(pods)).WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
		return check.ResultOK.ExpectMetricsIncrease(enterpriseTests.ExternalCiliumDNSProxySource(pods), "isovalent_external_dns_proxy_policy_l7_total"),
			check.ResultNone
	})
	return nil
}

func addPhantomServiceTests(ct *check.ConnectivityTest) (err error) {
	// Phantom service support has been introduced in Isovalent Enterprise for Cilium v1.13.2
	if ct.Params().MultiCluster == "" || ct.CiliumVersion.LT(semver.MustParse("1.13.2")) {
		return nil
	}

	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	mustGetTest(ct, "no-policies").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	mustGetTest(ct, "allow-all-except-world").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())

	// Traffic shall be dropped, because it is subject to the ingress/egress policy.
	mustGetTest(ct, "all-ingress-deny").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	mustGetTest(ct, "all-ingress-deny-knp").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	mustGetTest(ct, "all-egress-deny").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	mustGetTest(ct, "all-egress-deny-knp").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	mustGetTest(ct, "cluster-entity-multi-cluster").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())

	// Traffic shall be allowed, because it matches the cross-cluster policy.
	mustGetTest(ct, "client-egress").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())
	mustGetTest(ct, "client-egress-knp").WithSetupFunc(deploy.PhantomService).WithScenarios(enterpriseTests.PodToPhantomService())

	return
}

func addEgressGatewayHATests(ct *check.ConnectivityTest) (err error) {
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

	return nil
}

func mustGetTest(ct *check.ConnectivityTest, name string) *check.Test {
	test, err := ct.GetTest(name)
	if err != nil {
		panic(err)
	}
	return test
}

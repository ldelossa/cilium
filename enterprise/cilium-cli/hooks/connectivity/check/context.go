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

	appsv1 "k8s.io/api/apps/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	enterpriseK8s "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/k8s"
)

type EnterpriseConnectivityTest struct {
	*check.ConnectivityTest

	// clients for source and destination clusters.
	clients *deploymentClients
}

func NewEnterpriseConnectivityTest(ct *check.ConnectivityTest) *EnterpriseConnectivityTest {
	client, _ := enterpriseK8s.NewEnterpriseClient(ct.K8sClient())

	c := &deploymentClients{
		src: client,
		dst: client,
	}

	return &EnterpriseConnectivityTest{
		ConnectivityTest: ct,
		clients:          c,
	}
}

func (ect *EnterpriseConnectivityTest) NewEnterpriseTest(name string) *EnterpriseTest {
	ct := check.NewTest(name, ect.ConnectivityTest.Params().Verbose, ect.ConnectivityTest.Params().Debug)
	ect.ConnectivityTest.AddTest(ct)
	et := EnterpriseTest{
		Test:         ct,
		ctx:          ect,
		iegps:        make(map[string]*isovalentv1.IsovalentEgressGatewayPolicy),
		imgs:         make(map[string]*isovalentv1alpha1.IsovalentMulticastGroup),
		mcastDeploys: make(map[string]*appsv1.Deployment),
	}

	ct.WithSetupFunc(func(ctx context.Context, t *check.Test, ct *check.ConnectivityTest) error {
		return et.setup(ctx)
	})

	return &et
}

func (ect *EnterpriseTest) WithFeatureRequirements(reqs ...features.Requirement) *EnterpriseTest {
	ect.Test.WithFeatureRequirements(reqs...)
	return ect
}

func (ect *EnterpriseConnectivityTest) EntClients() []*enterpriseK8s.EnterpriseClient {
	return ect.clients.clients()
}

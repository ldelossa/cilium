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
	"fmt"
	"maps"

	"github.com/cilium/cilium-cli/connectivity/check"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	enterpriseK8s "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/k8s"
)

// createOrUpdateIEGP creates the IEGP and updates it if it already exists.
func createOrUpdateIEGP(ctx context.Context, client *enterpriseK8s.EnterpriseClient, iegp *isovalentv1.IsovalentEgressGatewayPolicy) error {
	_, err := check.CreateOrUpdatePolicy(ctx, client.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies(),
		iegp, func(current *isovalentv1.IsovalentEgressGatewayPolicy) bool {
			if maps.Equal(current.GetLabels(), iegp.GetLabels()) &&
				current.Spec.DeepEqual(&iegp.Spec) {
				return false
			}

			current.ObjectMeta.Labels = iegp.ObjectMeta.Labels
			current.Spec = iegp.Spec
			return true
		})

	return err
}

// deleteIEGP deletes a CiliumEgressGatewayPolicy from the cluster.
func deleteIEGP(ctx context.Context, client *enterpriseK8s.EnterpriseClient, iegp *isovalentv1.IsovalentEgressGatewayPolicy) error {
	if err := client.DeleteIsovalentEgressGatewayPolicy(ctx, iegp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s policy delete failed: %w", client.ClusterName(), iegp.Name, err)
	}

	return nil
}

// addiegps adds one or more CiliumEgressGatewayPolicy resources to the Test.
func (t *EnterpriseTest) addIEGPs(iegps ...*isovalentv1.IsovalentEgressGatewayPolicy) (err error) {
	t.iegps, err = check.RegisterPolicy(t.iegps, iegps...)
	return err
}

// applyPolicies applies all the Test's registered network policies.
func (t *EnterpriseTest) applyPolicies(ctx context.Context) error {
	if len(t.iegps) == 0 {
		return nil
	}

	// Apply all given Cilium Egress Gateway Policies.
	for _, iegp := range t.iegps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying CiliumEgressGatewayPolicy '%s' to namespace '%s'..", iegp.Name, iegp.Namespace)
			if err := createOrUpdateIEGP(ctx, client, iegp); err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
		}
	}

	// Register a finalizer with the Test immediately to enable cleanup.
	// If we return a cleanup closure from this function, cleanup cannot be
	// performed if the user cancels during the policy revision wait time.
	t.WithFinalizer(func() error {
		// Use a detached context to make sure this call is not affected by
		// context cancellation. This deletion needs to happen event when the
		// user interrupted the program.
		if err := t.deletePolicies(context.TODO()); err != nil {
			t.CiliumLogs(ctx)
			return err
		}

		return nil
	})

	if len(t.iegps) > 0 {
		t.Debugf("📜 Successfully applied %d IsovalentEgressGatewayPolicies", len(t.iegps))
	}

	return nil
}

// deletePolicies deletes a given set of network policies from the cluster.
func (t *EnterpriseTest) deletePolicies(ctx context.Context) error {
	if len(t.iegps) == 0 {
		return nil
	}

	// Delete all the Test's iegps from all clients.
	for _, iegp := range t.iegps {
		t.Infof("📜 Deleting CiliumEgressGatewayPolicy '%s' from namespace '%s'..", iegp.Name, iegp.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteIEGP(ctx, client, iegp); err != nil {
				return fmt.Errorf("deleting CiliumEgressGatewayPolicy: %w", err)
			}
		}
	}

	if len(t.iegps) > 0 {
		t.Debugf("📜 Successfully deleted %d IsovalentEgressGatewayPolicies", len(t.iegps))
	}

	return nil
}

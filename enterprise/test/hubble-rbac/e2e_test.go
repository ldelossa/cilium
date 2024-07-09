// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

//go:build enterprise_hubble_rbac_e2e

package hubblerbac

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

var (
	adminUser     = os.Getenv("ADMIN_OIDC_USER")
	adminPassword = os.Getenv("ADMIN_OIDC_PASSWORD")

	demoUser     = os.Getenv("DEMO_OIDC_USER")
	demoPassword = os.Getenv("DEMO_OIDC_PASSWORD")
)

func TestHubbleObserve(t *testing.T) {
	ctx := context.Background()

	t.Run("unauthenticated", func(t *testing.T) {
		// Logout to make sure we have no credentials before running each test
		hubble(ctx, "logout")
		defer hubble(ctx, "logout")

		// unauthenticated requests should fail
		out, err := hubble(ctx, "observe", "--namespace=kube-system")
		require.Error(t, err)
		assert.Contains(t, out, "Unauthenticated", "Should be unauthenticated")
	})

	t.Run("authenticated as admin", func(t *testing.T) {
		// Logout to make sure we have no credentials before running each test
		hubble(ctx, "logout")
		defer hubble(ctx, "logout")

		hubbleLogin(ctx, t, adminUser, adminPassword)

		t.Run("get all flows should succeed", func(t *testing.T) {
			out, err := hubble(ctx, "observe", "-o", "json")
			require.NoError(t, err)

			var flows []observerpb.GetFlowsResponse_Flow
			dec := json.NewDecoder(strings.NewReader(out))
			for dec.More() {
				var flow observerpb.GetFlowsResponse_Flow
				err := dec.Decode(&flow)
				require.NoError(t, err)
				flows = append(flows, flow)
			}
			require.NotEmpty(t, flows, "expected flows to be returned")
		})
		t.Run("get flows in kube-system should succeed", func(t *testing.T) {
			out, err := hubble(ctx, "observe", "-o", "json", "--namespace", "kube-system")
			require.NoError(t, err)

			var flows []observerpb.GetFlowsResponse_Flow
			dec := json.NewDecoder(strings.NewReader(out))
			for dec.More() {
				var flow observerpb.GetFlowsResponse_Flow
				err := dec.Decode(&flow)
				require.NoError(t, err)
				flows = append(flows, flow)
			}
			require.NotEmpty(t, flows, "expected flows to be returned")
		})
	})

	t.Run("authenticated as demo", func(t *testing.T) {
		// Logout to make sure we have no credentials before running each test
		hubble(ctx, "logout")
		defer hubble(ctx, "logout")

		hubbleLogin(ctx, t, demoUser, demoPassword)

		t.Run("get all flows should fail", func(t *testing.T) {
			out, err := hubble(ctx, "observe", "-o", "json")
			require.Error(t, err)
			assert.Contains(t, out, "PermissionDenied", "should get permission denied")
		})
		t.Run("get flows in kube-system should succeed", func(t *testing.T) {
			out, err := hubble(ctx, "observe", "-o", "json", "--namespace", "kube-system")
			require.NoError(t, err)

			var flows []observerpb.GetFlowsResponse_Flow
			dec := json.NewDecoder(strings.NewReader(out))
			for dec.More() {
				var flow observerpb.GetFlowsResponse_Flow
				err := dec.Decode(&flow)
				require.NoError(t, err)
				flows = append(flows, flow)
			}
			require.NotEmpty(t, flows, "expected flows to be returned")
		})

	})

}

func hubble(ctx context.Context, args ...string) (string, error) {
	_, fname, _, _ := runtime.Caller(0)
	hubbleDir := path.Join(
		path.Dir(fname), "..", "..", "..", "hubble", "enterprise",
	)

	args = append([]string{"run", hubbleDir}, args...)
	cmd := exec.CommandContext(ctx, "go", args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func hubbleLogin(ctx context.Context, t *testing.T, username, password string) {
	require.NotEmpty(t, password, "no password provided")

	passwordFile, err := os.CreateTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() {
		passwordFile.Close()
		os.Remove(passwordFile.Name())
	})
	_, err = passwordFile.WriteString(password)
	require.NoError(t, err)

	loginArgs := []string{
		"login",
		"--debug",
		"--grant-type", "password",
		"--user", username,
		"--password-file", passwordFile.Name(),
		"--scopes", "email",
	}
	_, err = hubble(ctx, loginArgs...)
	require.NoError(t, err)
}

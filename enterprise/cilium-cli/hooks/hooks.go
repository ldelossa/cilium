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
	"context"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/sysdump"
	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks/connectivity/tests"
	enterpriseFeatures "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/utils/features"
)

// EnterpriseHooks implements cli.Hooks interface to add connectivity tests and
// sysdump tasks that are specific to Isovalent Enterprise for Cilium.
type EnterpriseHooks struct {
	api.NopHooks

	ec   EnterpriseConnectivity
	Opts *EnterpriseOptions
}

// EnterpriseOptions are cilium enterprise specific options for tasks
type EnterpriseOptions struct {
	HubbleUINamespace string

	HubbleTimescapeReleaseName  string
	HubbleTimescapeSelector     string
	HubbleTimescapeNamespace    string
	HubbleTimescapeBugtoolFlags []string

	HubbleEnterpriseReleaseName string
	HubbleEnterpriseNamespace   string
}

func NewEnterpriseHook() *EnterpriseHooks {
	return &EnterpriseHooks{
		Opts: &EnterpriseOptions{
			HubbleTimescapeSelector:     "app.kubernetes.io/part-of=hubble-timescape",
			HubbleTimescapeReleaseName:  "hubble-timescape",
			HubbleTimescapeNamespace:    "hubble-timescape",
			HubbleUINamespace:           "hubble-ui",
			HubbleEnterpriseReleaseName: "hubble-enterprise",
			HubbleEnterpriseNamespace:   "kube-system",
		},
	}
}

// AddConnectivityTests registers connectivity tests that are specific to
// Isovalent Enterprise for Cilium.
func (eh *EnterpriseHooks) AddConnectivityTests(ct ...*check.ConnectivityTest) error {
	return eh.ec.addConnectivityTests(ct...)
}

// AddConnectivityTestFlags registers connectivity test flags that are specific to the
// Isovalent Enterprise for Cilium connectivity tests.
func (eh *EnterpriseHooks) AddConnectivityTestFlags(flags *pflag.FlagSet) {
	eh.ec.addConnectivityTestFlags(flags)
}

// AddSysdumpTasks registers sysdump tasks that are specific to Isovalent
// Enterprise for Cilium.
func (eh *EnterpriseHooks) AddSysdumpTasks(collector *sysdump.Collector) error {
	if err := enterpriseFeatures.ExtractFromSysdumpCollector(collector); err != nil {
		return err
	}
	return addSysdumpTasks(collector, eh.Opts)
}

func (eh *EnterpriseHooks) DetectFeatures(ctx context.Context, ct *check.ConnectivityTest) error {
	return enterpriseFeatures.Detect(ctx, ct)
}

func (eh *EnterpriseHooks) SetupAndValidate(ctx context.Context, ct *check.ConnectivityTest) error {
	var err error

	eh.ec.externalCiliumDNSProxyPods, err = tests.RetrieveExternalCiliumDNSProxyPods(ctx, ct)
	if err != nil {
		return err
	}

	// Setup the sniffers used by the mixed routing scenario. No op if either
	// fallback routing is not configured, or unsafe tests are disabled.
	mr, setup := tests.MixedRouting()
	eh.ec.mixedRoutingScenario = mr
	if err := setup(ctx, ct); err != nil {
		return err
	}

	return nil
}

func (eh *EnterpriseHooks) InitializeCommand(command *cobra.Command) {
	// This hook removes all subcommands except for those contained in `supportedCommands`.
	// Therefore, we show a help message only for the `cilium sysdump` usage.
	supportedCommands := []string{
		"sysdump",
		"version",
	}
	command.Short = "CLI to collect troubleshooting information for Isovalent Enterprise for Cilium"
	command.Long = ""
	command.Example = `# Collect sysdump from the entire cluster.
cilium sysdump

# Collect sysdump from specific nodes.
cilium sysdump --node-list node-a,node-b,node-c`
	for _, cmd := range command.Commands() {
		if !slices.Contains(supportedCommands, cmd.Name()) {
			cmd.Hidden = true
		}
		if cmd.Name() == "sysdump" {
			cmd.Flags().StringVar(&eh.Opts.HubbleUINamespace,
				"hubble-ui-namespace", eh.Opts.HubbleUINamespace,
				"The namespace Hubble UI is running in")
			cmd.Flags().StringVar(&eh.Opts.HubbleTimescapeReleaseName,
				"hubble-timescape-helm-release-name", eh.Opts.HubbleTimescapeReleaseName,
				"The Hubble Timescape Helm release name for which to get values")
			cmd.Flags().StringVar(&eh.Opts.HubbleTimescapeNamespace,
				"hubble-timescape-namespace", eh.Opts.HubbleTimescapeNamespace,
				"The namespace Hubble Timescape is running in")
			cmd.Flags().StringVar(&eh.Opts.HubbleTimescapeSelector,
				"hubble-timescape-selector", eh.Opts.HubbleTimescapeSelector,
				"The labels used to target Hubble Timescape pods")
			cmd.Flags().StringArrayVar(&eh.Opts.HubbleTimescapeBugtoolFlags,
				"hubble-timescape-bugtool-flags", nil,
				"Optional set of flags to pass to hubble timescape bugtool command.")
		}
	}
}

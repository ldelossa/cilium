//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"os"

	"github.com/cilium/cilium-cli/cli"
	cfsslLog "github.com/cloudflare/cfssl/log"
	"golang.org/x/exp/slices"

	"github.com/isovalent/cilium/enterprise/cilium-cli/hooks"
)

func main() {
	supportedCommands := []string{
		"sysdump",
		"version",
	}

	// Hide unwanted cfssl log messages
	cfsslLog.Level = cfsslLog.LevelWarning
	eeOpts := hooks.EnterpriseOptions{
		HubbleTimescapeSelector:    "app.kubernetes.io/part-of=hubble-timescape",
		HubbleTimescapeReleaseName: "hubble-timescape",
		HubbleTimescapeNamespace:   "hubble-timescape",
		HubbleUINamespace:          "hubble-ui",
	}
	command := cli.NewCiliumCommand(&hooks.EnterpriseHooks{
		Opts: &eeOpts,
	})
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
			cmd.Flags().StringVar(&eeOpts.HubbleUINamespace,
				"hubble-ui-namespace", eeOpts.HubbleUINamespace,
				"The namespace Hubble UI is running in")

			cmd.Flags().StringVar(&eeOpts.HubbleTimescapeReleaseName,
				"hubble-timescape-helm-release-name", eeOpts.HubbleTimescapeReleaseName,
				"The Hubble Timescape Helm release name for which to get values")
			cmd.Flags().StringVar(&eeOpts.HubbleTimescapeNamespace,
				"hubble-timescape-namespace", eeOpts.HubbleTimescapeNamespace,
				"The namespace Hubble Timescape is running in")
			cmd.Flags().StringVar(&eeOpts.HubbleTimescapeSelector,
				"hubble-timescape-selector", eeOpts.HubbleTimescapeSelector,
				"The labels used to target Hubble Timescape pods")

		}
	}
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
	command := cli.NewCiliumCommand(&hooks.EnterpriseHooks{})
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
	}
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

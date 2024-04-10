//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-dbg/cmd"
)

// bfdCmd is the root command of the BFD subsystem
var bfdCmd = &cobra.Command{
	Use:   "bfd",
	Short: "BFD subsystem information",
}

// bfdPeersCmd is the command for dumping BFD peers
var bfdPeersCmd = &cobra.Command{
	Use:     "peers",
	Aliases: []string{"sessions"},
	Short:   "List state of BFD peers",
	Long:    "List current state of all configured BFD peers",
	Run:     bfdStatedbTableCmd.Run,
}

func init() {
	cmd.RootCmd.AddCommand(bfdCmd)
	bfdCmd.AddCommand(bfdPeersCmd)
}

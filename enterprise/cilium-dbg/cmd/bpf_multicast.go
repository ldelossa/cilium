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

var bpfMulticastCmd = &cobra.Command{
	Use:     "multicast",
	Aliases: []string{"mcast"},
	Short:   "Access to multicast maps",
}

func init() {
	cmd.BPFCmd.AddCommand(bpfMulticastCmd)
	bpfMulticastCmd.AddCommand(bpfMulticastGroupCmd)
	bpfMulticastCmd.AddCommand(bpfMulticastSubscriberCmd)
}

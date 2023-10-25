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
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
)

var bpfMulticastGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage the multicast groups.",
}

var bpfMulticastGroupListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List the multicast groups.",
	Long:    "List the multicast groups configured on the node.",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multicast group list")

		groupV4Map, err := maps_multicast.OpenGroupV4OuterMap(maps_multicast.GroupOuter4MapName)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find multicast bpf maps")
				return
			}

			Fatalf("Cannot open multicast bpf maps: %s", err)
		}

		groups, err := groupV4Map.List()
		if err != nil {
			Fatalf("Error listing multicast groups: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(groups); err != nil {
				Fatalf("error getting output of map in %s: %s\n", command.OutputOptionString(), err)
			}
			return
		}
		printGroupList(groups)
	},
}

func printGroupList(groups []netip.Addr) {
	// sort groups by address
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Compare(groups[j]) < 0
	})

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Group Address")
	for _, group := range groups {
		fmt.Fprintf(w, "%s\n", group.String())
	}
	w.Flush()
}

func init() {
	bpfMulticastGroupCmd.AddCommand(bpfMulticastGroupListCmd)
	command.AddOutputOption(bpfMulticastGroupListCmd)
}

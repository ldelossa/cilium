// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"
)

const (
	egressListUsage = "List egress policy entries.\n" + lpmWarningMessage
)

type egressPolicy struct {
	SourceIP   string
	DestCIDR   string
	EgressIP   string
	GatewayIPs []string
}

var bpfEgressListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List egress policy entries",
	Long:    egressListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress list")

		if err := egressmap.OpenEgressMaps(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find egress gateway bpf maps")
				return
			}

			Fatalf("Cannot open egress gateway bpf maps: %s", err)
		}

		bpfEgressList := []egressPolicy{}
		parse := func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			gatewayIPs := []string{}
			for _, gatewayIP := range val.GetGatewayIPs() {
				gatewayIPs = append(gatewayIPs, gatewayIP.String())
			}

			bpfEgressList = append(bpfEgressList, egressPolicy{
				SourceIP:   key.GetSourceIP().String(),
				DestCIDR:   key.GetDestCIDR().String(),
				EgressIP:   val.GetEgressIP().String(),
				GatewayIPs: gatewayIPs,
			})
		}

		if err := egressmap.EgressPolicyMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of egress policy map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfEgressList); err != nil {
				Fatalf("error getting output of map in %s: %s\n", command.OutputOptionString(), err)
			}
			return
		}

		if len(bpfEgressList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", lpmWarningMessage)
		} else {
			printEgressList(bpfEgressList)
		}
	},
}

func printEgressList(egressList []egressPolicy) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Source IP\tDestination CIDR\tEgress IP\tGateway\t")
	for _, ep := range egressList {
		fmt.Fprintf(w, "%s\t%s\t%s\t0 => %s\n", ep.SourceIP, ep.DestCIDR, ep.EgressIP, ep.GatewayIPs[0])
		for i := 1; i < len(ep.GatewayIPs); i++ {
			fmt.Fprintf(w, "\t\t\t%d => %s\n", i, ep.GatewayIPs[i])
		}
	}

	w.Flush()
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressListCmd)
	command.AddOutputOption(bpfEgressListCmd)
}

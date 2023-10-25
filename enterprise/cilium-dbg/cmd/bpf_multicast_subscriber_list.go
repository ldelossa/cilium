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

const (
	allGroupsKW = "all"
	remoteKW    = "Remote Node"
	localKW     = "Local Endpoint"
)

var bpfMulticastSubscriberCmd = &cobra.Command{
	Use:     "subscriber",
	Aliases: []string{"sub"},
	Short:   "Manage the multicast subscribers.",
}

var bpfMulticastGroupSubscriberListCmd = &cobra.Command{
	Use:     "list < group-address | all >",
	Aliases: []string{"ls"},
	Short:   "List the multicast subscribers for the given group.",
	Long: `List the multicast subscribers for the given group. 
To get the subscribers for all the groups, use 'cilium bpf multicast subscriber list all'.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multicast subscriber list")

		var groups []netip.Addr
		var err error

		groupAddr, all, err := parseMulticastGroupSubscriberListArgs(args)
		if err != nil {
			Fatalf("invalid argument: %s\n", err)
		}

		groupV4Map, err := maps_multicast.OpenGroupV4OuterMap(maps_multicast.GroupOuter4MapName)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find multicast bpf maps")
				return
			}
			Fatalf("Failed to open multicast bpf maps: %s", err)
		}

		if all {
			groups, err = groupV4Map.List()
			if err != nil {
				Fatalf("Failed to list multicast groups: %s", err)
			}
		} else {
			groups = append(groups, groupAddr)
		}

		outputGroups(groupV4Map, groups)
	},
}

// subscriberData is used to store the subscribers of a multicast group
type subscriberData struct {
	GroupAddr   netip.Addr
	Subscribers []maps_multicast.SubscriberV4
}

func outputGroups(groupV4Map maps_multicast.GroupV4Map, groupAddrs []netip.Addr) {
	var allGroups []subscriberData

	for _, groupAddr := range groupAddrs {
		groupData := subscriberData{
			GroupAddr: groupAddr,
		}

		subscriberMap, err := groupV4Map.Lookup(groupAddr)
		if err != nil {
			Fatalf("Failed to lookup multicast group %s: %s", groupAddr, err)
		}

		subscribers, err := subscriberMap.List()
		if err != nil {
			Fatalf("Failed to list multicast subscribers for group %s: %s", groupAddr, err)
		}

		for _, sub := range subscribers {
			groupData.Subscribers = append(groupData.Subscribers, *sub)
		}

		allGroups = append(allGroups, groupData)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(allGroups); err != nil {
			Fatalf("error getting output of map in %s: %s\n", command.OutputOptionString(), err)
		}
		return
	}
	printSubscriberList(allGroups)
}

func printSubscriberList(subscribers []subscriberData) {
	sort.Slice(subscribers, func(i, j int) bool {
		return subscribers[i].GroupAddr.Compare(subscribers[j].GroupAddr) < 0
	})

	// sort subscribers in each group
	for _, group := range subscribers {
		sort.Slice(group.Subscribers, func(i, j int) bool {
			return group.Subscribers[i].SAddr.Compare(group.Subscribers[j].SAddr) < 0
		})
	}

	w := tabwriter.NewWriter(os.Stdout, 16, 1, 0, ' ', 0)
	fmt.Fprintln(w, "Group\tSubscriber\tType\t")
	for _, subData := range subscribers {
		fmt.Fprintf(w, "%s\t", subData.GroupAddr)
		for i, sub := range subData.Subscribers {
			if i > 0 {
				// move by one tab to accommodate group address
				fmt.Fprintf(w, "\t")
			}
			fmt.Fprintf(w, "%s\t", sub.SAddr)
			fmt.Fprintf(w, "%s\t", getSubscriberType(sub.IsRemote))
			fmt.Fprintf(w, "\n")
		}

		if len(subData.Subscribers) == 0 {
			fmt.Fprintf(w, "\n")
		}
	}
	w.Flush()
}

func getSubscriberType(isRemote bool) string {
	if isRemote {
		return remoteKW
	}
	return localKW
}

func parseMulticastGroupSubscriberListArgs(args []string) (netip.Addr, bool, error) {
	if len(args) != 1 {
		return netip.Addr{}, false, fmt.Errorf("expected exactly one argument")
	}

	if args[0] == allGroupsKW {
		return netip.Addr{}, true, nil
	}

	addr, err := netip.ParseAddr(args[0])
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("invalid group address: %s", err)
	}

	return addr, false, nil
}

func init() {
	bpfMulticastSubscriberCmd.AddCommand(bpfMulticastGroupSubscriberListCmd)
	command.AddOutputOption(bpfMulticastGroupSubscriberListCmd)
}

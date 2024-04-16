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
	"github.com/cilium/cilium/cilium-dbg/cmd"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
)

// bfdStatedbTableCmd is the command generated for the "bfd-peers" statedb table
var bfdStatedbTableCmd = cmd.StatedbTableCommand[*types.BFDPeerStatus]("bfd-peers")

func init() {
	cmd.StatedbCmd.AddCommand(bfdStatedbTableCmd)
}

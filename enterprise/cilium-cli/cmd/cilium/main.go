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

	"github.com/cilium/cilium/cilium-cli/cli"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks"
	_ "github.com/cilium/cilium/cilium-cli/logging" // necessary to disable unwanted cfssl log messages
)

func main() {
	command := cli.NewCiliumCommand(hooks.NewEnterpriseHook())
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

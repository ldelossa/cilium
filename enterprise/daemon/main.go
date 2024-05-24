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
	"log"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/daemon/daemonplugins"
	_ "github.com/cilium/cilium/enterprise/fips"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	agentHive := hive.New(
		EnterpriseAgent,
	)
	vp := agentHive.Viper()

	list, err := daemonplugins.Initialize(vp, daemonplugins.DefaultPlugins)
	if err != nil {
		log.Fatalf("failed to initialize plugins: %v", err)
	}

	agentCmd := cmd.NewAgentCmd(agentHive)
	if err := daemonplugins.AddFlags(vp, agentCmd, list); err != nil {
		log.Fatalf("unable to apply cilium CLI options: %v", err)
	}

	if err := daemonplugins.AddServerOptions(list); err != nil {
		log.Fatalf("unable to add server options: %v", err)
	}

	cmd.Execute(agentCmd)
}

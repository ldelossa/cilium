// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"

	_ "github.com/cilium/cilium/enterprise/fips"
	"github.com/cilium/cilium/hubble-relay/cmd"
)

func main() {
	if err := cmd.New().Execute(); err != nil {
		os.Exit(1)
	}
}

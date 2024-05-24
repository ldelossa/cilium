// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/cilium-dbg/cmd"
	_ "github.com/cilium/cilium/enterprise/cilium-dbg/cmd"
	_ "github.com/cilium/cilium/enterprise/fips"
)

func main() {
	cmd.Execute()
}

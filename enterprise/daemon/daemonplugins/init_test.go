//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package daemonplugins

import (
	"log"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	aggregation "github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation"
	export "github.com/cilium/cilium/enterprise/plugins/hubble-flow-export"
)

func TestPlugins(t *testing.T) {
	vp := viper.New()
	list, err := Initialize(vp, DefaultPlugins)
	if err != nil {
		log.Fatalf("failed to initialize plugins: %v", err)
	}

	if err := AddServerOptions(list); err != nil {
		log.Fatalf("unable to add server options: %v", err)
	}

	_, ok := list[0].(aggregation.Plugin)
	require.True(t, ok, "first plugin should be aggregation plugin")
	// export must come after aggregation
	_, ok = list[1].(export.Plugin)
	require.True(t, ok, "second plugin should be export plugin")
}

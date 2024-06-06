// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	dummyDevCfg = testutils.NewTestEndpoint()
	dummyEPCfg  = testutils.NewTestEndpoint()
)

// TestHashDatapath is done in this package just for easy access to dummy
// configuration objects.
func TestHashDatapath(t *testing.T) {
	var cfg datapath.ConfigWriter
	hv := hive.New(
		provideNodemap,
		cell.Provide(
			func() datapath.BandwidthManager { return &fakeTypes.BandwidthManager{} },
			func() sysctl.Sysctl { return sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc") },
			config.NewHeaderfileWriter,
			fakeTypes.NewNodeAddressing,
		),
		cell.Invoke(func(writer_ datapath.ConfigWriter) {
			cfg = writer_
		}),
	)

	tlog := hivetest.Logger(t)
	require.NoError(t, hv.Start(tlog, context.TODO()))
	t.Cleanup(func() { require.Nil(t, hv.Stop(tlog, context.TODO())) })

	h := newDatapathHash()
	baseHash := h.String()

	// Ensure we get different hashes when config is added
	h = hashDatapath(cfg, &localNodeConfig, &dummyDevCfg, &dummyEPCfg)
	dummyHash := h.String()
	require.NotEqual(t, dummyHash, baseHash)

	// Ensure we get the same base hash when config is removed via Reset()
	h.Reset()
	require.Equal(t, h.String(), baseHash)
	require.NotEqual(t, h.String(), dummyHash)

	// Ensure that with a copy of the endpoint config we get the same hash
	newEPCfg := dummyEPCfg
	h = hashDatapath(cfg, &localNodeConfig, &dummyDevCfg, &newEPCfg)
	require.NotEqual(t, h.String(), baseHash)
	require.Equal(t, h.String(), dummyHash)

	// Even with different endpoint IDs, we get the same hash
	//
	// This is the key to avoiding recompilation per endpoint; static
	// data substitution is performed via pkg/elf instead.
	newEPCfg.Id++
	h = hashDatapath(cfg, &localNodeConfig, &dummyDevCfg, &newEPCfg)
	require.NotEqual(t, h.String(), baseHash)
	require.Equal(t, h.String(), dummyHash)

	// But when we configure the endpoint differently, it's different
	newEPCfg = testutils.NewTestEndpoint()
	newEPCfg.Opts.SetBool("foo", true)
	h = hashDatapath(cfg, &localNodeConfig, &dummyDevCfg, &newEPCfg)
	require.NotEqual(t, h.String(), baseHash)
	require.NotEqual(t, h.String(), dummyHash)
}

var provideNodemap = cell.Provide(func() nodemap.MapV2 {
	return fake.NewFakeNodeMapV2()
})

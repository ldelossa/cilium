// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package source

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowOverwrite(t *testing.T) {
	require.Equal(t, true, AllowOverwrite(Kubernetes, Kubernetes))
	require.Equal(t, true, AllowOverwrite(Kubernetes, CustomResource))
	require.Equal(t, true, AllowOverwrite(Kubernetes, KVStore))
	require.Equal(t, true, AllowOverwrite(Kubernetes, Local))
	require.Equal(t, true, AllowOverwrite(Kubernetes, KubeAPIServer))
	require.Equal(t, false, AllowOverwrite(Kubernetes, LocalAPI))
	require.Equal(t, false, AllowOverwrite(Kubernetes, Generated))
	require.Equal(t, false, AllowOverwrite(Kubernetes, Restored))
	require.Equal(t, false, AllowOverwrite(Kubernetes, Unspec))

	require.Equal(t, true, AllowOverwrite(CustomResource, CustomResource))
	require.Equal(t, true, AllowOverwrite(CustomResource, KVStore))
	require.Equal(t, true, AllowOverwrite(CustomResource, Local))
	require.Equal(t, true, AllowOverwrite(CustomResource, KubeAPIServer))
	require.Equal(t, false, AllowOverwrite(CustomResource, LocalAPI))
	require.Equal(t, false, AllowOverwrite(CustomResource, Kubernetes))
	require.Equal(t, false, AllowOverwrite(CustomResource, Generated))
	require.Equal(t, false, AllowOverwrite(CustomResource, Restored))
	require.Equal(t, false, AllowOverwrite(CustomResource, Unspec))

	require.Equal(t, false, AllowOverwrite(KVStore, Kubernetes))
	require.Equal(t, false, AllowOverwrite(KVStore, CustomResource))
	require.Equal(t, true, AllowOverwrite(KVStore, KVStore))
	require.Equal(t, true, AllowOverwrite(KVStore, Local))
	require.Equal(t, true, AllowOverwrite(KVStore, KubeAPIServer))
	require.Equal(t, false, AllowOverwrite(KVStore, LocalAPI))
	require.Equal(t, false, AllowOverwrite(KVStore, Generated))
	require.Equal(t, false, AllowOverwrite(KVStore, Restored))
	require.Equal(t, false, AllowOverwrite(KVStore, Unspec))

	require.Equal(t, false, AllowOverwrite(Local, Kubernetes))
	require.Equal(t, false, AllowOverwrite(Local, CustomResource))
	require.Equal(t, false, AllowOverwrite(Local, KVStore))
	require.Equal(t, false, AllowOverwrite(Local, Generated))
	require.Equal(t, true, AllowOverwrite(Local, Local))
	require.Equal(t, true, AllowOverwrite(Local, KubeAPIServer))
	require.Equal(t, false, AllowOverwrite(Local, LocalAPI))
	require.Equal(t, false, AllowOverwrite(Local, Restored))
	require.Equal(t, false, AllowOverwrite(Local, Unspec))

	require.Equal(t, false, AllowOverwrite(KubeAPIServer, Kubernetes))
	require.Equal(t, false, AllowOverwrite(KubeAPIServer, CustomResource))
	require.Equal(t, false, AllowOverwrite(KubeAPIServer, KVStore))
	require.Equal(t, false, AllowOverwrite(KubeAPIServer, Generated))
	require.Equal(t, false, AllowOverwrite(KubeAPIServer, Local))
	require.Equal(t, true, AllowOverwrite(KubeAPIServer, KubeAPIServer))
	require.Equal(t, false, AllowOverwrite(KubeAPIServer, LocalAPI))
	require.Equal(t, false, AllowOverwrite(KubeAPIServer, Restored))
	require.Equal(t, false, AllowOverwrite(KubeAPIServer, Unspec))

	require.Equal(t, true, AllowOverwrite(LocalAPI, Kubernetes))
	require.Equal(t, true, AllowOverwrite(LocalAPI, CustomResource))
	require.Equal(t, true, AllowOverwrite(LocalAPI, KVStore))
	require.Equal(t, true, AllowOverwrite(LocalAPI, Local))
	require.Equal(t, true, AllowOverwrite(LocalAPI, KubeAPIServer))
	require.Equal(t, true, AllowOverwrite(LocalAPI, LocalAPI))
	require.Equal(t, false, AllowOverwrite(LocalAPI, Generated))
	require.Equal(t, false, AllowOverwrite(LocalAPI, Restored))
	require.Equal(t, false, AllowOverwrite(LocalAPI, Unspec))

	require.Equal(t, true, AllowOverwrite(Generated, Kubernetes))
	require.Equal(t, true, AllowOverwrite(Generated, CustomResource))
	require.Equal(t, true, AllowOverwrite(Generated, KVStore))
	require.Equal(t, true, AllowOverwrite(Generated, Local))
	require.Equal(t, true, AllowOverwrite(Generated, KubeAPIServer))
	require.Equal(t, true, AllowOverwrite(Generated, LocalAPI))
	require.Equal(t, true, AllowOverwrite(Generated, Generated))
	require.Equal(t, false, AllowOverwrite(Generated, Restored))
	require.Equal(t, false, AllowOverwrite(Generated, Unspec))

	require.Equal(t, true, AllowOverwrite(Restored, Kubernetes))
	require.Equal(t, true, AllowOverwrite(Restored, CustomResource))
	require.Equal(t, true, AllowOverwrite(Restored, KVStore))
	require.Equal(t, true, AllowOverwrite(Restored, Local))
	require.Equal(t, true, AllowOverwrite(Restored, KubeAPIServer))
	require.Equal(t, true, AllowOverwrite(Restored, LocalAPI))
	require.Equal(t, true, AllowOverwrite(Restored, Generated))
	require.Equal(t, true, AllowOverwrite(Restored, Restored))
	require.Equal(t, false, AllowOverwrite(Restored, Unspec))

	require.Equal(t, true, AllowOverwrite(Unspec, Kubernetes))
	require.Equal(t, true, AllowOverwrite(Unspec, CustomResource))
	require.Equal(t, true, AllowOverwrite(Unspec, KVStore))
	require.Equal(t, true, AllowOverwrite(Unspec, Local))
	require.Equal(t, true, AllowOverwrite(Unspec, KubeAPIServer))
	require.Equal(t, true, AllowOverwrite(Unspec, LocalAPI))
	require.Equal(t, true, AllowOverwrite(Unspec, Generated))
	require.Equal(t, true, AllowOverwrite(Unspec, Restored))
	require.Equal(t, true, AllowOverwrite(Unspec, Unspec))
}

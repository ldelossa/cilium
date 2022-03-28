// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

const (
	StateMapName4   = "cilium_srv6_state_v4"
	StateMapName6   = "cilium_srv6_state_v6"
	MaxStateEntries = 16384
)

func CreateMaps() {
	CreatePolicyMaps()
	CreateSIDMap()
	CreateVRFMaps()
}

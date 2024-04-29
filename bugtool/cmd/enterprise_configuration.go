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

func init() {
	ExtraCommands = append(ExtraCommands, enterpriseCommands)
}

func enterpriseCommands(confDir string, _ string, k8sPods []string) []string {
	bpfMapsPath := []string{
		"tc/globals/cilium_egress_gw_ha_policy_v4",
		"tc/globals/cilium_egress_gw_ha_ct_v4",
	}
	bpfCommands := bpfMapDumpCommands(bpfMapsPath)
	if len(k8sPods) > 0 {
		bpfCommands = k8sPerPodCommands(bpfCommands, k8sPods)
	}

	infoCommands := []string{
		"cilium-dbg bpf egress-ha list",
		"cilium-dbg bpf egress-ha ct list",
	}
	return append(bpfCommands, k8sPerPodCopyCommands(infoCommands, k8sPods)...)
}

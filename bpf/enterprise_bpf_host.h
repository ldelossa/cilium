/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_cilium_mesh.h"

#undef host_egress_policy_hook
static __always_inline int
host_egress_policy_hook(struct __ctx_buff *ctx __maybe_unused,
			__u32 src_sec_identity __maybe_unused,
			__s8 *ext_err __maybe_unused)
{
#if defined(CILIUM_MESH)
	{
		__be16 proto;
		void *data, *data_end;
		struct iphdr *ip4;

		if (!validate_ethertype(ctx, &proto))
			return DROP_UNSUPPORTED_L2;

		if (proto != bpf_htons(ETH_P_IP))
			return CTX_ACT_OK;

		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		return cilium_mesh_policy_ingress(ctx, ip4, src_sec_identity, ext_err);
	}
#endif

       return CTX_ACT_OK;
}

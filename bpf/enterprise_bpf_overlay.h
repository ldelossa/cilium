/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_cilium_mesh.h"

#undef overlay_ingress_policy_hook
static __always_inline int
overlay_ingress_policy_hook(struct __ctx_buff *ctx __maybe_unused,
			    struct iphdr *ip4 __maybe_unused,
			    __u32 dst_id __maybe_unused,
			    __s8 *ext_err __maybe_unused)
{
#if defined(CILIUM_MESH)
	return cilium_mesh_policy_ingress(ctx, ip4, dst_id, ext_err);
#endif

	return CTX_ACT_OK;
}

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENTERPRISE_NODEPORT_H_
#define __LIB_ENTERPRISE_NODEPORT_H_

#include "enterprise_cilium_mesh.h"

#undef nodeport_nat_egress_ipv4_hook
static __always_inline int
nodeport_nat_egress_ipv4_hook(struct __ctx_buff *ctx __maybe_unused,
			      struct iphdr *ip4 __maybe_unused,
			      __u32 dst_sec_identity __maybe_unused,
			      struct ipv4_ct_tuple *tuple __maybe_unused,
			      int l4_off __maybe_unused,
			      __s8 *ext_err __maybe_unused)
{
#ifdef CILIUM_MESH
	__u32 src_identity = ctx_load_meta(ctx, CB_SRC_LABEL) ?: WORLD_IPV4_ID;
	int ret;

	ret = cilium_mesh_nodeport_egress_policy(ctx, ip4, dst_sec_identity, tuple, l4_off,
						 ext_err);
	if (ret != CTX_ACT_OK)
		return send_drop_notify_ext(ctx, src_identity, dst_sec_identity, 0,
					ret, *ext_err, CTX_ACT_DROP, METRIC_EGRESS);
#endif
	return CTX_ACT_OK;
}

#endif /* __LIB_ENTERPRISE_NODEPORT_H_ */


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
#if defined(CILIUM_MESH) && !defined(IS_BPF_OVERLAY)
	__u32 src_sec_identity = ctx_load_meta(ctx, CB_SRC_LABEL) ?: WORLD_IPV4_ID;
	int ret;

	ret = cilium_mesh_policy_egress(ctx, ip4, dst_sec_identity, tuple, l4_off, ext_err);
	if (ret != CTX_ACT_OK)
		return send_drop_notify_ext(ctx, src_sec_identity, dst_sec_identity, 0, ret,
					    *ext_err, CTX_ACT_DROP, METRIC_EGRESS);
#endif
	return CTX_ACT_OK;
}

#undef nodeport_rev_dnat_ingress_ipv4_hook
static __always_inline int
nodeport_rev_dnat_ingress_ipv4_hook(struct __ctx_buff *ctx __maybe_unused,
				    struct iphdr *ip4 __maybe_unused,
				    struct ipv4_ct_tuple *tuple __maybe_unused,
				    __u32 *tunnel_endpoint __maybe_unused,
				    __u32 *src_sec_identity __maybe_unused,
				    __u32 *dst_sec_identity __maybe_unused)
{
#if defined(CILIUM_MESH) && !defined(IS_BPF_OVERLAY)
	if (!ct_has_nodeport_egress_entry4(get_ct_map4(tuple), tuple, NULL, false)) {
		struct remote_endpoint_info *info;
		struct remote_endpoint_info *src;

		/* CiliumMesh: this is a hacky check to forward a packet, which is a reply,
		 * via the tunnel to the remote GW instance. The non-hacky check (to be
		 * implemented) is to add a mapping IP => remote GW instead of REMOTE_NODE_ID.
		 *
		 * ctx_snat_done == src is from a CiliumMesh EP. Again, its a hack.
		 */
		if (ctx_snat_done(ctx)) {
			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
			if (info && identity_is_remote_node(info->sec_identity)) {
				src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
				if (src)
					*src_sec_identity = src->sec_identity;

				*tunnel_endpoint = ip4->daddr;
				*dst_sec_identity = info->sec_identity;

				return CTX_ACT_REDIRECT;
			}
		}

		return CTX_ACT_OK;
	}
#endif

	return -1;
}

#endif /* __LIB_ENTERPRISE_NODEPORT_H_ */


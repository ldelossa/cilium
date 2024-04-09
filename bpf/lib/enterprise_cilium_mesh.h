/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENTERPRISE_CILIUM_MESH_H_
#define __LIB_ENTERPRISE_CILIUM_MESH_H_

#ifdef CILIUM_MESH

#include "lib/policy.h"
#include "lib/policy_log.h"

static __always_inline void *cilium_mesh_endpoint_policy_map(__u32 ip __maybe_unused)
{
#if !defined(SKIP_POLICY_MAP)
	struct endpoint_key key = {};

	key.ip4 = ip;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&CILIUM_MESH_POLICY_MAP, &key);
#endif
	return 0;
}

static __always_inline int
__cilium_mesh_policy_can_access(struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
				__be16 dport, __u8 proto, int l4_off, __u8 *match_type, int dir,
				__u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	int ret;
	void *map;
	/* XXX */ __u32 local_id = 0;
	/* XXX */ bool is_untracked_fragment = false;
	/* XXX */ __u16 ethertype = ETH_P_IP;

	map = cilium_mesh_endpoint_policy_map(ip);
	if (!map)
		return CTX_ACT_OK; /* XXX ? actually, isn't this a fatal error? need to report somehow */

	/* shouldn't this be set here instead? XXX: check with the normal path */
	*audited = 0;

	ret = __policy_can_access(map, ctx, local_id, dst_id, ethertype, dport, proto,
				  l4_off, dir, is_untracked_fragment, match_type,
				  ext_err, proxy_port);
	if (ret >= 0)
		return ret;

	cilium_dbg(ctx, DBG_POLICY_DENIED, local_id, dst_id);

#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif
	return ret;
}

#define EGRESS_POLICY	!!(CT_EGRESS)
#define INGRESS_POLICY	!(CT_EGRESS)

static __always_inline int
cilium_mesh_policy_can_egress4(struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
			       __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
			       __u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	return __cilium_mesh_policy_can_access(ctx, ip, dst_id, dport, proto, l4_off,
			match_type, EGRESS_POLICY, audited, ext_err, proxy_port);
}

static __always_inline int
cilium_mesh_policy_can_ingress4(struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
			       __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
			       __u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	return __cilium_mesh_policy_can_access(ctx, ip, dst_id, dport, proto, l4_off,
			match_type, INGRESS_POLICY, audited, ext_err, proxy_port);
}

static __always_inline int
cilium_mesh_policy_egress(struct __ctx_buff *ctx __maybe_unused,
			  struct iphdr *ip4 __maybe_unused,
			  __u32 dst_sec_identity __maybe_unused,
			  struct ipv4_ct_tuple *tuple __maybe_unused,
			  int l4_off __maybe_unused,
			  __s8 *ext_err __maybe_unused)
{
#ifndef IS_BPF_OVERLAY
	__u8 policy_match_type = 0;
	int verdict = CTX_ACT_OK;
	__u16 proxy_port = 0;
	__u8 audited = 0;

	verdict = cilium_mesh_policy_can_egress4(ctx, ip4->saddr, dst_sec_identity,
						 tuple->dport, ip4->protocol, l4_off,
						 &policy_match_type, &audited,
						 ext_err, &proxy_port);

	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		/* XXX: implement me */
	}

	/*
	 * XXX conntrack if (verdict != CTX_ACT_OK || ct_status != CT_ESTABLISHED)
	 */
	 if (verdict != CTX_ACT_OK) {
		send_policy_verdict_notify(ctx, dst_sec_identity, tuple->dport,
					   ip4->protocol, POLICY_EGRESS, 0,
					   verdict, proxy_port, policy_match_type, audited,
					   0 /* auth_type */ );
		return verdict;
	 }
#endif
	return CTX_ACT_OK;
}

static __always_inline int
cilium_mesh_policy_ingress(struct __ctx_buff *ctx,
			   struct iphdr *ip4,
			   __u32 dst_id, __s8 *ext_err)
{
	__u8 policy_match_type = 0;
	__u16 proxy_port = 0;
	__u8 audited = 0;
	__be16 dport;
	int verdict;
	int l4_off;
	int ret;

	// XXX tcp&udp ok; what about other traffic?
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	ret = l4_load_port(ctx, l4_off + 2, &dport);
	if (IS_ERR(ret))
		return ret;

	verdict = cilium_mesh_policy_can_ingress4(ctx, ip4->daddr, dst_id,
						  dport, ip4->protocol, l4_off,
						  &policy_match_type, &audited,
						  ext_err, &proxy_port);

	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		/* XXX: implement me */
	}

	/*
	 * XXX: we don't use CT here, yet, needs to be like this
	 * if (verdict != CTX_ACT_OK || ct_status != CT_ESTABLISHED)
	 */
	if (verdict != CTX_ACT_OK)
		send_policy_verdict_notify(ctx, dst_id, dport, ip4->protocol,
					   POLICY_INGRESS, 0, verdict, proxy_port,
					   policy_match_type, audited, 0 /* auth_type */ );

	return verdict;
}

static __always_inline int
cilium_mesh_snat_v4_needs_masquerade(struct __ctx_buff *ctx __maybe_unused,
				     struct ipv4_nat_target *target __maybe_unused)
{
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && \
  defined(ENABLE_INTER_CLUSTER_SNAT) && !defined(IS_BPF_OVERLAY)
	struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* SNAT the packet which has been forwarded by a remote client GW.
	 * This is needed so that replies pass through this GW, and only
	 * then to the remote client GW.
	 */
	src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
	if (src && identity_is_remote_node(src->sec_identity)) {
		target->addr = IPV4_MASQUERADE;
		return 1;
	}
#endif

	return 0;
}

#endif /* CILIUM_MESH */
#endif /* __LIB_ENTERPRISE_CILIUM_MESH_H_ */

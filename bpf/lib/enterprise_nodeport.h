/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENTERPRISE_NODEPORT_H_
#define __LIB_ENTERPRISE_NODEPORT_H_

#undef nodeport_nat_egress_ipv4_hook
static __always_inline int
nodeport_nat_egress_ipv4_hook(struct __ctx_buff *ctx __maybe_unused,
			      struct iphdr *ip4 __maybe_unused,
			      __u32 dst_sec_identity __maybe_unused,
			      struct ipv4_ct_tuple *tuple __maybe_unused,
			      int l4_off __maybe_unused,
			      __s8 *ext_err __maybe_unused)
{
	return CTX_ACT_OK;
}

#endif /* __LIB_ENTERPRISE_NODEPORT_H_ */


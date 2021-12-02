/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "lib/identity.h"

#include "maps.h"

#ifdef ENABLE_EGRESS_GATEWAY

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

static __always_inline
int fill_egress_ct_key(struct ipv4_ct_tuple *ct_key, struct __ctx_buff *ctx,
		       const struct iphdr *ip4, int l4_off)
{
	struct {
		__be16 sport;
		__be16 dport;
	} ports;

	if (ctx_load_bytes(ctx, l4_off, &ports, 4) < 0)
		return DROP_INVALID;

	ct_key->saddr = ip4->saddr;
	ct_key->daddr = ip4->daddr;
	ct_key->nexthdr = ip4->protocol;
	ct_key->sport = ports.sport;
	ct_key->dport = ports.dport;

	return 0;
}

static __always_inline
struct egress_ct_entry *lookup_ip4_egress_ct(struct ipv4_ct_tuple *ct_key)
{
	return map_lookup_elem(&EGRESS_CT_MAP, ct_key);
}

static __always_inline
void update_egress_ct_entry(struct ipv4_ct_tuple *ct_key, __be32 gateway)
{
	struct egress_ct_entry egress_ct = {
		.gateway_ip = gateway
	};

	map_update_elem(&EGRESS_CT_MAP, ct_key, &egress_ct, 0);
}

static __always_inline
struct egress_gw_policy_entry *lookup_ip4_egress_gw_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_POLICY_MAP, &key);
}

static __always_inline
__be32 pick_egress_gateway(const struct egress_gw_policy_entry *policy)
{
	unsigned int index = get_prandom_u32() % policy->size;

	/* Just being extra defensive here while keeping the verifier happy.
	 * Userspace should always guarantee the invariant:
	 *     policy->size < EGRESS_MAX_GATEWAY_NODES"
	 */
	index %= EGRESS_MAX_GATEWAY_NODES;

	return policy->gateway_ips[index];
}

#endif /* ENABLE_EGRESS_GATEWAY */
#endif /* __LIB_EGRESS_POLICIES_H_ */

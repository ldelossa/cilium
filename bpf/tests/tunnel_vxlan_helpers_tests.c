// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include "bpf/ctx/skb.h"
#include "pktgen.h"

#define TUNNEL_PROTOCOL TUNNEL_PROTOCOL_VXLAN
#define TUNNEL_PORT 8472
#define TUNNEL_PORT_BAD 0
#define VXLAN_VNI 0xDEADBE

#include "node_config.h"
#include "lib/common.h"

static __always_inline int
mk_packet(struct __ctx_buff *ctx) {
	struct pktgen builder;
	struct udphdr *l4;
	struct vxlanhdr *vx;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one,
					  (__u8 *)mac_two,
					  v4_node_one,
					  v4_node_two,
					  666,
					  bpf_htons(TUNNEL_PORT));
	if (!l4)
		return TEST_ERROR;

	vx = pktgen__push_default_vxlanhdr(&builder);
	if (!vx)
		return TEST_ERROR;

	vx->vx_vni = bpf_htonl(VXLAN_VNI << 8);

	/* we won't sniff into the encap'd packet, so just use the default */
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "tunnel_skb_is_vxlan_v4_success")
static __always_inline int
pktgen_vxlan_mock_check1(struct __ctx_buff *ctx) {
	return mk_packet(ctx);
}

CHECK("tc", "tunnel_skb_is_vxlan_v4_success")
int check1(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	assert(tunnel_skb_is_vxlan_v4(data, data_end, ipv4, TUNNEL_PORT));

	test_finish();
}

PKTGEN("tc", "tunnel_skb_is_vxlan_v4_failure")
static __always_inline int
pktgen_vxlan_mock_check2(struct __ctx_buff *ctx) {
	return mk_packet(ctx);
}

CHECK("tc", "tunnel_skb_is_vxlan_v4_failure")
int check2(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	assert(!tunnel_skb_is_vxlan_v4(data, data_end, ipv4, TUNNEL_PORT_BAD));

	test_finish();
}

PKTGEN("tc", "tunnel_vxlan_get_vni_success")
static __always_inline int
pktgen_vxlan_mock_check3(struct __ctx_buff *ctx) {
	return mk_packet(ctx);
}

CHECK("tc", "tunnel_vxlan_get_vni_success")
int check3(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	assert(tunnel_vxlan_get_vni(data, data_end, ipv4) == VXLAN_VNI);

	test_finish();
}


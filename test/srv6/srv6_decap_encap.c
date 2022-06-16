// SPDX-License-Identifier: GPL-2.0
//
// Taken from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/progs/test_tc_tunnel.c?h=v5.12

/* In-place tunneling */

//#include <stdbool.h>
//#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/mpls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ERROR(ret) do {\
		char fmt[] = "ERROR line:%d ret:%d\n";\
		bpf_trace_printk(fmt, sizeof(fmt), __LINE__, ret); \
	} while (0)

#define	UDP_PORT		5555
#define	MPLS_OVER_UDP_PORT	6635
#define	ETH_OVER_UDP_PORT	7777

#define BPF_ADJ_ROOM_MAC 1

#define	EFAULT		14	/* Bad address */
#define	EINVAL		22	/* Invalid argument */

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
       __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define ntohs(x)                __builtin_bswap16(x)
# define htons(x)                __builtin_bswap16(x)
# define ntohl(x)                __builtin_bswap32(x)
# define htonl(x)                __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
       __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define ntohs(x)                (x)
# define htons(x)                (x)
# define ntohl(x)                (x)
# define htonl(x)                (x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

#define BPF_F_ADJ_ROOM_NO_CSUM_RESET (1ULL << 5)

#ifndef NEXTHDR_ROUTING
# define NEXTHDR_ROUTING 43
#endif

struct srv6_srh {
	struct ipv6_rt_hdr rthdr;
	__u8 first_segment;
	__u8 flags;
	__u16 reserved;
	struct in6_addr segments[0];
};

static int decap_internal(struct __sk_buff *skb, char proto)
{
	__u16 new_proto = bpf_htons(ETH_P_IP);
	int nexthdr_offset, shrink = 0;

	switch (proto) {
	case NEXTHDR_ROUTING:
		nexthdr_offset = ETH_HLEN + sizeof(struct ipv6hdr) +
				 offsetof(struct srv6_srh, rthdr.nexthdr);
		if (bpf_skb_load_bytes(skb, nexthdr_offset, &proto,
				       sizeof(proto)) < 0)
			return TC_ACT_SHOT;

		shrink = sizeof(struct srv6_srh) + sizeof(struct in6_addr);

		switch (proto) {
		case IPPROTO_IPIP:
			goto parse_outer_ipv4;
		case IPPROTO_IPV6:
			goto parse_outer_ipv6;
		default:
			return TC_ACT_SHOT;
		}
	case IPPROTO_IPIP:
parse_outer_ipv4:
		if (bpf_skb_change_proto(skb, new_proto, 0) < 0)
			return TC_ACT_SHOT;
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
					&new_proto, sizeof(new_proto), 0) < 0)
			return TC_ACT_SHOT;
		shrink += sizeof(struct iphdr);
		break;
	case IPPROTO_IPV6:
parse_outer_ipv6:
		shrink += sizeof(struct ipv6hdr);
		break;
	default:
		return TC_ACT_OK;
	}

    	if (bpf_skb_adjust_room(skb, -shrink, BPF_ADJ_ROOM_MAC,
    				BPF_F_ADJ_ROOM_FIXED_GSO))
    		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

SEC("decap")
int decap_f(struct __sk_buff *skb)
{
	__u8 nexthdr;

	if (skb->protocol == __bpf_constant_htons(ETH_P_IPV6)) {
		if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr),
				       &nexthdr, sizeof(nexthdr)) < 0)
			return TC_ACT_SHOT;

		return decap_internal(skb, nexthdr);
	}

	return TC_ACT_OK;
	
}

static __always_inline int
srv6_encapsulation(struct __sk_buff *skb, int growth, __u16 new_payload_len,
		   __u8 nexthdr, struct in6_addr *saddr, struct in6_addr *sid)
{
	__u32 len = sizeof(struct ipv6hdr) - 2 * sizeof(struct in6_addr);
	struct ipv6hdr new_ip6 = {
		.version     = 0x6,
		.payload_len = bpf_htons(new_payload_len),
		.nexthdr     = nexthdr,
		.hop_limit   = IPDEFTTL,
	};

#ifndef ENABLE_SRV6_REDUCED_ENCAP
	/* If reduced encapsulation is disabled, the next header will be the
	 * segment routing header.
	 */
	new_ip6.nexthdr = NEXTHDR_ROUTING;
#endif /* ENABLE_SRV6_REDUCED_ENCAP */

	/* Add room between Ethernet and network headers. */
	if (bpf_skb_adjust_room(skb, growth, BPF_ADJ_ROOM_MAC,
				BPF_F_ADJ_ROOM_NO_CSUM_RESET))
		return 1;
	if (bpf_skb_store_bytes(skb, ETH_HLEN, &new_ip6, len, 0) < 0)
		return 2;
	if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    saddr, sizeof(struct in6_addr), 0) < 0)
		return 2;
	if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    sid, sizeof(struct in6_addr), 0) < 0)
		return 2;

#ifndef ENABLE_SRV6_REDUCED_ENCAP
	{
	/* If reduced encapsulation mode is disabled, we need to add a segment
	 * routing header.
	 */
	struct srv6_srh srh = {
		.rthdr.nexthdr       = nexthdr,
		.rthdr.hdrlen        = sizeof(struct in6_addr) / 8,
		.rthdr.type          = IPV6_SRCRT_TYPE_4,
		.rthdr.segments_left = 0,
		.first_segment       = 0,
		.flags               = 0,
		.reserved            = 0,
	};
	int segment_list_offset = ETH_HLEN + sizeof(struct ipv6hdr) +
				  offsetof(struct srv6_srh, segments);

	if (bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr),
				&srh, sizeof(struct srv6_srh), 0) < 0)
		return 2;
	if (bpf_skb_store_bytes(skb, segment_list_offset, sid,
				sizeof(struct in6_addr), 0) < 0)
		return 2;
	}
#endif /* ENABLE_SRV6_REDUCED_ENCAP */
	return 0;
}

SEC("encap")
int encap_f(struct __sk_buff *skb)
{
	struct in6_addr src_sid = {.in6_u.u6_addr8 = {0xfd, 0x04, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13}};
	struct in6_addr dst_sid = {.in6_u.u6_addr8 = {0xfd, 0x04, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11}};
	void *data = (void *)(long long)skb->data, *data_end = (void *)(long long)skb->data_end;
	__u16 outer_proto = bpf_htons(ETH_P_IPV6);
	__u16 new_payload_len;
	// struct ipv6hdr *ip6;
	struct iphdr *ip4;
	int growth, ret;
	__u8 nexthdr;

	switch (skb->protocol) {
	case __bpf_constant_htons(ETH_P_IP):
		ip4 = (struct iphdr *)(data + ETH_HLEN);
		if ((void *)ip4 + sizeof(struct iphdr) > data_end)
			return TC_ACT_SHOT;

		if ((bpf_ntohl(ip4->daddr) & 0xff000000) != 0x0a000000)
			return TC_ACT_OK;

		nexthdr = IPPROTO_IPIP;
		/* IPv4's tot_len fields has the size of the entire packet
		 * including headers while IPv6's payload_len field has only
		 * the size of the IPv6 payload. Therefore, without IPv6
		 * extension headers (none here), the outer IPv6 payload_len
		 * is equal to the inner IPv4 tot_len.
		 */
		new_payload_len = bpf_ntohs(ip4->tot_len) - (__u16)(ip4->ihl << 2) + sizeof(struct iphdr);

		/* We need to change skb->protocol and the corresponding packet
		 * field because the L3 protocol will now be IPv6.
		 */
		if (bpf_skb_change_proto(skb, outer_proto, 0) < 0)
			return TC_ACT_SHOT;
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
				    &outer_proto, sizeof(outer_proto), 0) < 0)
			return TC_ACT_SHOT;
		/* skb_change_proto above grows the packet from IPv4 header
		 * length to IPv6 header length. It adds the additional space
		 * before the inner L3 header, in the same place we will later
		 * add the outer IPv6 header.
		 * Thus, deduce this space from the next packet growth.
		 */
		growth = sizeof(struct iphdr);

#ifndef ENABLE_SRV6_REDUCED_ENCAP
		growth += sizeof(struct srv6_srh) + sizeof(struct in6_addr);
		new_payload_len += sizeof(struct srv6_srh) + sizeof(struct in6_addr);
#endif

		ret = srv6_encapsulation(skb, growth, new_payload_len, nexthdr,
					 &src_sid, &dst_sid);
		if (ret != 0)
			return TC_ACT_SHOT;
		break;
	case __bpf_constant_htons(ETH_P_IPV6):
		/*ip6 = (struct ipv6hdr *)(data + ETH_HLEN);
		if ((void *)ip6 + sizeof(struct ipv6hdr) > data_end)
			return TC_ACT_SHOT;

		nexthdr = IPPROTO_IPV6;
		new_payload_len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr);
		growth = sizeof(struct ipv6hdr);

		ret = srv6_encapsulation(skb, growth, new_payload_len, nexthdr,
					 &src_sid, &dst_sid);
		if (ret != 0)
			return TC_ACT_SHOT;*/
		break;
	}
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

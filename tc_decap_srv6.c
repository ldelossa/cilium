// SPDX-License-Identifier: GPL-2.0
//
// Taken from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/progs/test_tc_tunnel.c?h=v5.12

/* In-place tunneling */

#include <stdbool.h>
#include <string.h>

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

struct gre_hdr {
	__be16 flags;
	__be16 protocol;
} __attribute__((packed));

union l4hdr {
	struct udphdr udp;
	struct gre_hdr gre;
};

struct v4hdr {
	struct iphdr ip;
	union l4hdr l4hdr;
	__u8 pad[16];			/* enough space for L2 header */
} __attribute__((packed));

struct v6hdr {
	struct ipv6hdr ip;
	union l4hdr l4hdr;
	__u8 pad[16];			/* enough space for L2 header */
} __attribute__((packed));

static int decap_internal(struct __sk_buff *skb, int off, int len, char proto)
{
	__u16 h_proto = bpf_htons(ETH_P_IP);
	struct ethhdr ethhdr;
	struct gre_hdr greh;
	struct udphdr udph;
	int olen = len;

	switch (proto) {
	case IPPROTO_IPIP:
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
					&h_proto, sizeof(h_proto), 0) < 0)
			return TC_ACT_OK;
		/* Fallthrough */
	case IPPROTO_IPV6:
		if (bpf_skb_load_bytes(skb, 0, &ethhdr, sizeof(ethhdr)) < 0)
			return TC_ACT_OK;
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
					&ethhdr.h_dest, sizeof(ethhdr.h_dest), 0) < 0)
			return TC_ACT_OK;
		/* k8s2's enp0s8 MAC address. */
		ethhdr.h_dest[3] = 0x0e;
		ethhdr.h_dest[4] = 0x92;
		ethhdr.h_dest[5] = 0x0e;
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
					&ethhdr.h_dest, sizeof(ethhdr.h_dest), 0) < 0)
			return TC_ACT_OK;
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
					&h_proto, sizeof(h_proto), 0) < 0)
			return TC_ACT_OK;
		break;
	case IPPROTO_GRE:
		olen += sizeof(struct gre_hdr);
		if (bpf_skb_load_bytes(skb, off + len, &greh, sizeof(greh)) < 0)
			return TC_ACT_OK;
		switch (bpf_ntohs(greh.protocol)) {
		case ETH_P_MPLS_UC:
			olen += sizeof(__u32);
			break;
		case ETH_P_TEB:
			olen += ETH_HLEN;
			break;
		}
		break;
	case IPPROTO_UDP:
		olen += sizeof(struct udphdr);
		if (bpf_skb_load_bytes(skb, off + len, &udph, sizeof(udph)) < 0)
			return TC_ACT_OK;
		switch (bpf_ntohs(udph.dest)) {
		case MPLS_OVER_UDP_PORT:
			olen += sizeof(__u32);
			break;
		case ETH_OVER_UDP_PORT:
			olen += ETH_HLEN;
			break;
		}
		break;
	default:
		return TC_ACT_OK;
	}

   	if (bpf_skb_adjust_room(skb, -olen, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO) < 0)
    		return TC_ACT_SHOT;

	return TC_ACT_REDIRECT;
}

static int decap_ipv4(struct __sk_buff *skb)
{
	struct iphdr iph_outer;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph_outer,
			       sizeof(iph_outer)) < 0)
		return TC_ACT_OK;

	if (iph_outer.ihl != 5)
		return TC_ACT_OK;

	return decap_internal(skb, ETH_HLEN, sizeof(iph_outer),
			      iph_outer.protocol);
}

static int decap_ipv6(struct __sk_buff *skb)
{
	struct ipv6hdr iph_outer;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph_outer,
			       sizeof(iph_outer)) < 0)
		return TC_ACT_OK;

	return decap_internal(skb, ETH_HLEN, sizeof(iph_outer),
			      iph_outer.nexthdr);
}

static int display(struct __sk_buff *skb)
{
	const char fmt[] = "SRv6 packet decapsulated and analyzed: 10.0.0.%u:%u -> 192.168.56.12:8080 %s\n";
	__u16 sport = 0, dport = 0;
	__u32 saddr, daddr;
	__u32 ipv4_hdrlen;
	struct tcphdr tcp;
	struct iphdr ip4;
	char syn_flag[] = "SYN";
	char ack_flag[] = "ACK";
	char pushack_flag[] = "PUSH+ACK";
	char finack_flag[] = "FIN+ACK";
	char no_flag[] = "";
	char *flag;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip4,
			       sizeof(ip4)) < 0)
		return TC_ACT_OK;

	flag = no_flag;
	if (ip4.protocol == IPPROTO_UDP || ip4.protocol == IPPROTO_TCP) {
		ipv4_hdrlen = ip4.ihl << 2;
		if (bpf_skb_load_bytes(skb, ETH_HLEN + ipv4_hdrlen, &tcp,
				       sizeof(tcp)) < 0)
			return TC_ACT_OK;
		sport = ntohs(tcp.source);
		dport = ntohs(tcp.dest);

		if (ip4.protocol == IPPROTO_TCP) {
			if (tcp.syn && !tcp.ack) {
				flag = syn_flag;
			} else if (tcp.fin && tcp.ack) {
				flag = finack_flag;
			} else if (tcp.psh && tcp.ack) {
				flag = pushack_flag;
			} else if (tcp.ack) {
				flag = ack_flag;
			}
		}
	}

	saddr = ntohl(ip4.saddr) & 0xff;
	daddr = ntohl(ip4.daddr) & 0xff;
	bpf_trace_printk(fmt, sizeof(fmt), saddr, sport, flag);
	return TC_ACT_REDIRECT;
}

SEC("decap")
int decap_f(struct __sk_buff *skb)
{
	int ret;

	switch (skb->protocol) {
	case __bpf_constant_htons(ETH_P_IP):
		ret = decap_ipv4(skb);
		break;
	case __bpf_constant_htons(ETH_P_IPV6):
		ret = decap_ipv6(skb);
		break;
	default:
		/* does not match, ignore */
		return TC_ACT_OK;
	}

	if (ret != TC_ACT_REDIRECT)
		return ret;

	ret = display(skb);
	if (ret != TC_ACT_REDIRECT)
		return ret;

	return bpf_redirect(3, 0);
}

char __license[] SEC("license") = "GPL";

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_TUNNEL_H_
#define __LIB_TUNNEL_H_

#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

/* The high-order bit of the Geneve option type indicates that
 * this is a critical option.
 *
 * https://www.rfc-editor.org/rfc/rfc8926.html#name-tunnel-options
 */
#define GENEVE_OPT_TYPE_CRIT	0x80

/* Geneve option used to carry service addr and port for DSR.
 *
 * Class = 0x014B (Cilium according to [1])
 * Type  = 0x1   (vendor-specific)
 *
 * [1]: https://www.iana.org/assignments/nvo3/nvo3.xhtml#geneve-option-class
 */
#define DSR_GENEVE_OPT_CLASS	0x014B
#define DSR_GENEVE_OPT_TYPE	(GENEVE_OPT_TYPE_CRIT | 0x01)
#define DSR_IPV4_GENEVE_OPT_LEN	\
	((sizeof(struct geneve_dsr_opt4) - sizeof(struct geneve_opt_hdr)) / 4)
#define DSR_IPV6_GENEVE_OPT_LEN	\
	((sizeof(struct geneve_dsr_opt6) - sizeof(struct geneve_opt_hdr)) / 4)

struct geneve_opt_hdr {
	__be16 opt_class;
	__u8 type;
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 length:5,
	     rsvd:3;
#else
	__u8 rsvd:3,
	     length:5;
#endif
};

struct geneve_dsr_opt4 {
	struct geneve_opt_hdr hdr;
	__be32	addr;
	__be16	port;
	__u16	pad;
};

struct geneve_dsr_opt6 {
	struct geneve_opt_hdr hdr;
	struct in6_addr addr;
	__be16	port;
	__u16	pad;
};

struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 opt_len:6,
	     ver:2;
	__u8 rsvd:6,
	     critical:1,
	     control:1;
#else
	__u8 ver:2,
	     opt_len:6;
	__u8 control:1,
	     critical:1,
	     rsvd:6;
#endif
	__be16 protocol_type;
	__u8 vni[3];
	__u8 reserved;
};

struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

static __always_inline __u32
tunnel_vni_to_sec_identity(__be32 vni)
{
	return bpf_ntohl(vni) >> 8;
}

/*
 * Returns true if the skb associated with data pointers is a vxlan encapsulated
 * packet.
 *
 * The determination is made by comparing the UDP destination port with
 * the tunnel_port provided to the function.
 */
static __always_inline bool
tunnel_skb_is_vxlan_v4(void *data, void *data_end, struct iphdr *ipv4,
		       __u16 tunnel_port)
{
	struct udphdr *udp = NULL;
	__u32 l3_size = 0;

	if (ipv4->protocol != IPPROTO_UDP)
		return false;

	l3_size = ipv4->ihl * 4;

	if (data + sizeof(struct ethhdr) + l3_size + sizeof(struct udphdr)
	    + sizeof(struct vxlanhdr) > data_end)
		return false;

	udp = (struct udphdr *)(data + sizeof(struct ethhdr) + l3_size);

	if (udp->dest == bpf_htons(tunnel_port))
		return true;

	return false;
}

/*
 * Returns the VNI in the native host's endian format of a xvlan encap'd packet.
 *
 * The caller must ensure the skb associated with these data buffers are infact
 * a vxlan encapsulated packet before invoking this function.
 *
 * This can be done by calling 'tunnel_skb_is_vxlan_v4'
 *
 */
static __always_inline __u32
tunnel_vxlan_get_vni(void *data, void *data_end, struct iphdr *ipv4) {
	int l3_size = ipv4->ihl * 4;
	struct vxlanhdr *hdr;

	if (data + sizeof(struct ethhdr) + l3_size + sizeof(struct udphdr)
	    + sizeof(struct vxlanhdr) > data_end)
		return 0;

	hdr = (struct vxlanhdr *)(data + sizeof(struct ethhdr) + l3_size +
	       sizeof(struct udphdr));

	return bpf_ntohl(hdr->vx_vni) >> 8;
}

#endif /* __LIB_TUNNEL_H_ */

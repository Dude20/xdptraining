/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

// Debugging map array
struct bpf_map_def SEC("maps") xdp_dbg_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(int),
	.max_entries = 15,
};




/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);


	//printf("Test\n");
	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ipv6 = nh->pos;
	//int hdrsize = sizeof(*ipv6);

	if(ipv6 + 1 > data_end)
		return -1;
	
	nh->pos += 1;//hdrsize;
	*ip6hdr = ipv6;

	return ipv6->nexthdr;
}
/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{

	struct icmp6hdr *icmp6 = nh->pos;
	//int hdrsize = sizeof(*icmp6);
	
	if(icmp6 + 1 > data_end)
		return -1;
	
	*icmp6hdr = icmp6;
	nh->pos += 1;

	return icmp6->icmp6_type;
}


SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6h;
	struct icmp6hdr *icmpv6h;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	int ip6Type;
	int* dbgPtr;
	int indexLoc;
	int debug[10];
	//int i;

	/* Start next header cursor position at data start */
	nh.pos = data;


	/* Packet parsing in stepsout_testet correct?), and bounds checking.
	 */

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (bpf_ntohs(nh_type) != ETH_P_IPV6)
		goto out;

	// This here is an attempt at debug output
	indexLoc = 0;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = 1;
	
	/* Assignment additions go below here */
	nh_type = parse_ip6hdr(&nh, data_end, &ipv6h);
	ip6Type = nh_type;
	if(nh_type != 58) /*NEXTHDR_ICMP*/ //IPPROTO_ICMPV6
		goto out;

	// This here is an attempt at debug output
	indexLoc = 1;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = nh_type;
	// This here is an attempt at debug output
	indexLoc = 2;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = IPPROTO_ICMPV6;


	nh_type = parse_icmp6hdr(&nh,data_end,&icmpv6h);
	if(nh_type == -1)// && !(nh.pos + 8 > data_end)
		goto out;

	// This here is an attempt at debug output
	indexLoc = 3;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = nh_type;


	if(icmpv6h == 0)
		goto out;
		
	// For some reason the sequence appears to be this constant.
	if(bpf_ntohs(icmpv6h->icmp6_sequence) < 16636)
	  	goto out;


	// This here is an attempt at debug output
	indexLoc = 4;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = (unsigned short)icmpv6h->icmp6_sequence;
	// This here is an attempt at debug output
	indexLoc = 5;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = (unsigned short)bpf_ntohs(icmpv6h->icmp6_sequence);

	// This here is the logic I actually wanted to do but does not seem to work
	// if(((unsigned short)bpf_ntohs(icmpv6h->icmp6_sequence))%2 == 1)
	// 	goto out;
	// if(((unsigned short)bpf_ntohs(icmpv6h->icmp6_dataun.u_echo.sequence))%2 == 1)
	// 	goto out;
	
	// This here is an attempt at debug output
	indexLoc = 10;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = (unsigned short)bpf_ntohs(icmpv6h->icmp6_dataun.u_echo.sequence);
	indexLoc = 11;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = ((unsigned short)bpf_ntohs(icmpv6h->icmp6_dataun.u_echo.sequence))%2;


	// This here is an attempt at debug output
	indexLoc = 6;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = (unsigned short)bpf_htons(icmpv6h->icmp6_sequence);
	indexLoc = 7;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = (unsigned short)icmpv6h->icmp6_dataun.u_echo.sequence;
	indexLoc = 8;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = (unsigned short)icmpv6h->icmp6_dataun.un_data16[0];
	indexLoc = 9;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out; 
	dbgPtr[0] = (unsigned short)icmpv6h->icmp6_dataun.un_data16[1];
	indexLoc = 12;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if (dbgPtr == NULL)
		goto out;
	dbgPtr[0] = icmpv6h->icmp6_dataun.u_echo.identifier;
	indexLoc = 13;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if (dbgPtr == NULL)
		goto out;
	dbgPtr[0] = icmpv6h->icmp6_cksum;

	action = XDP_ABORTED;
	

	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
out:

	// Try and edit the output to reflect being redirected here
	indexLoc = 0;
	dbgPtr = bpf_map_lookup_elem(&xdp_dbg_map,&indexLoc);
	if(dbgPtr == NULL)
		goto out2; 
	dbgPtr[0] = 0;
out2:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */

}

char _license[] SEC("license") = "GPL";

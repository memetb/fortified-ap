#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

//
//                  --- [tap0] -- [nic0]
//                 /
// user -- [bond0] ---- ...
//               ^ \
//               |  --- [tapN] -- [nicN]
//               |
//         (YOU ARE HERE)
//
// ATTACH TO BOND INTERFACE ON EGRESS
//
// packets coming from the slave interfaces will be marked with 0xCFAE

// Define an array to store the sequence counter
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(max_entries, 1);
		__type(key, __u32);
		__type(value, __u32);	 // sequence counter
} seq_num_map SEC(".maps");

static __always_inline __u16 get_sequence_number()
{
    // get sequence number
    __u32 key = 0;
    __u32* seq_num = bpf_map_lookup_elem(&seq_num_map, &key);
    if (!seq_num) {
        return 0;
    }

    __sync_fetch_and_add(seq_num, 1);
    return (__u16)(__u32)(*seq_num) & PACKET_SEQUENCE_MASK;
}

SEC("tc")
int egress_tag(struct __sk_buff *skb)
{
    // packet was received from slave - it's already been sequence tagged
    // by the sending end (i.e. other host). Let the ingress filter strip it
    if (skb->mark == mark){
        log("[egress_mangle_and_tag:%d] ignoring %x %x", skb->ingress_ifindex, skb->mark, mark);
        return TC_ACT_OK;
    }

		// Access packet data
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;

    struct custom_header header_data;
    if (bpf_skb_load_bytes(skb, 0, &header_data, sizeof(header_data.eth)) < 0) {
        log("[egress_mangle_and_tag:%d] can't load ethernet header", skb->ingress_ifindex);
        return TC_ACT_OK; // TODO: make this confiugrable
    }

    // do not alter any of the ARP communications - their duplication doesn't matter anyways
    if( header_data.eth.h_proto == bpf_htons(ETH_P_ARP)) {
        log("[egress_mangle_and_tag:%d] received ARP packet - ignoring", skb->ingress_ifindex);
        return TC_ACT_OK;
    }

    // Expand packet by 32-bits (4 bytes), add the sequence number and the original
    // frame protocol type and replace the protocol to reserved
    if (bpf_skb_adjust_room(skb, 4, BPF_ADJ_ROOM_MAC, 0) < 0) {
        log("[egress_mangle_and_tag:%d] unable to adjust room (err=%d) - size is %d",
            skb->ingress_ifindex, res, skb->len);
        return TC_ACT_OK;
    }

    // PAYLOAD IS ADJUSTED, REFETCH DATA

		// Access packet data
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;

    // Ensure we have enough room for the Ethernet header + custom header
    struct ethhdr *eth = data;
    eth = data;
    if ((void *)(eth + 1) + 4 > data_end) {
        log("[egress_mangle_and_tag:%d] adjusted packet ethernet header is too short", skb->ingress_ifindex);
        return TC_ACT_SHOT;  // Drop if packet is too short
    }

    header_data.data.sequence = get_sequence_number();
    header_data.data.protocol = header_data.eth.h_proto;
    header_data.eth.h_proto = bpf_htons(ETH_P_802_EX1); // Change EtherType to custom value


    // Use bpf_skb_store_bytes to modify the eth_type
    if (bpf_skb_store_bytes(skb, 0, &header_data, sizeof(header_data), BPF_F_RECOMPUTE_CSUM ) < 0) {
        log("[egress_mangle_and_tag:%d] unable to modify header", skb->ingress_ifindex);
        return TC_ACT_SHOT;
    }

    log("[egress_mangle_and_tag:%d] tagged packet with serial: %d (type: 0x%x -> 0x%x) (size: %d)",
        skb->ingress_ifindex,
        header_data.data.sequence & PACKET_SEQUENCE_MASK,
        header_data.data.protocol,
        header_data.eth.h_proto,
        skb->len);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

/*
 To install:
 tc filter add dev bond0 egress basic action bpf obj /usr/share/fortified_ap/tc_egress.o sec tc

 uninstall:
 tc filter del dev bond0 egress

 maybe:
 modprobe cls_basic
 tc qdisc add dev bond0 clsact
 */

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
// ATTACH TO BOND INTERFACE ON INGRESS


// Define a hash map to store recent packet hashes
struct {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16*1024); // the number of hash entries dictates how far back we're looking
		__type(key, __u16);		 // sequence
		__type(value, __u16);	 // nothing
} seen_packets SEC(".maps");

SEC("tc")
int ingress_deduplicate(struct __sk_buff *skb)
{
    if (skb->mark != mark) {
        // packet is not coming to us from our slave interfaces, it is coming from
        // the "outside". Do not strip or do anything.
        return TC_ACT_OK;
    }

    skb->mark = 0; // remove mark so that we don't re-process this packet

		// Access packet data
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;
    int len = data_end - data;

    struct custom_header header;
    // Ensure we have enough room for the Ethernet header + counter
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) + sizeof(header.data.sequence) > data_end) {
        return TC_ACT_OK;  // Drop if packet is too short
    }

    if( eth->h_proto == bpf_htons(ETH_P_ARP)) {
        log("[ingress_deduplicate:%d] received ARP packet - ignoring", skb->ingress_ifindex);
        return TC_ACT_OK;
    }

    // get the sequence number from the end of the packet buffer
    __u16 sequence;
    if (bpf_skb_load_bytes(skb, len - sizeof(sequence), &sequence, sizeof(sequence)) < 0)
        return TC_ACT_OK;

    __u16 nothing = 0;
    if (bpf_map_update_elem(&seen_packets, &sequence, &nothing, BPF_NOEXIST) == 0) {

        log("[ingress_deduplicate:%d] packet sequence number is %d a DUP",
            skb->ingress_ifindex, sequence, eth->h_proto);
        return TC_ACT_SHOT;

    } else {
        return TC_ACT_OK;
    };
}

char LICENSE[] SEC("license") = "GPL";

/*
  install:
  sudo tc filter add dev bond0 ingress basic action bpf obj ingress_strip.o sec tc

  uninstall:
  sudo tc filter del dev bond0 ingress

 */

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
    __uint(max_entries, 512*1024);
		__type(key, __u16);		 // sequence
		__type(value, __u64);	 // timestamp
} seen_packets SEC(".maps");

#define DEDUP_WINDOW_NS 1500000000  // 1.5s // TODO: MAKE THIS CONFIGURABLE

SEC("tc")
int ingress_deduplicate(struct __sk_buff *skb)
{
    if (skb->mark != mark) {
        // packet is not coming to us from our slave interfaces, it is coming from
        // the "outside". Do not strip or do anything.
        return TC_ACT_OK;
    }

		// Access packet data
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;
    int len = data_end - data;

    struct custom_header header;
    // Ensure we have enough room for the Ethernet header + counter
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) + sizeof(header.data.sequence) > data_end) {
        return TC_ACT_SHOT;  // Drop if packet is too short
    }

    // get the sequence number
    if (bpf_skb_load_bytes(skb, len - sizeof(header.data.sequence), &header.data.sequence, sizeof(header.data.sequence)) < 0) {
        return TC_ACT_SHOT;
        log("[ingress_deduplicate:%d] received ARP packet - ignoring", skb->ingress_ifindex);
    }


    // Get current timestamp
    __u64 now = bpf_ktime_get_ns();

    // Look up in map
    __u64 *seen = bpf_map_lookup_elem(&seen_packets, &header.data.sequence);
    if (seen){
        // Check if within dedup window
        if (now - *seen < DEDUP_WINDOW_NS) {
            return TC_ACT_SHOT;  // Drop duplicate packet
        }
    }

    // Not a duplicate, add to map
    bpf_map_update_elem(&seen_packets, &header.data.sequence, &now, BPF_ANY);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

/*
  install:
  sudo tc filter add dev bond0 ingress basic action bpf obj ingress_strip.o sec tc

  uninstall:
  sudo tc filter del dev bond0 ingress

 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

SEC("tc")
int egress_mangle_and_tag(struct __sk_buff *skb)
{
    // packet was received from slave - it's already been sequence tagged
    // by the sending end (i.e. other host). Let the ingress filter strip it
    if (skb->mark == 0xCFAE)
        return TC_ACT_OK;

		// Access packet data
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;

    struct ethhdr header_data;
    if (bpf_skb_load_bytes(skb, 0, &header_data, sizeof(header_data)) < 0) {
        // load the ethernet header
        return TC_ACT_SHOT;
    }
    // Expand packet by 32-bits (4 bytes), add the sequence number and the original
    // frame protocol type and replace the protocol to reserved
    __u32 key = 0;
    __u32* seq_num = bpf_map_lookup_elem(&seq_num_map, &key);
    if (!seq_num) {
        return TC_ACT_OK;
    }

    if (bpf_skb_adjust_room(skb, 4, BPF_ADJ_ROOM_MAC, 0) < 0) {
        return TC_ACT_OK;
    }

		// Access packet data
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;

    // Ensure we have enough room for the Ethernet header + custom header
    struct ethhdr *eth = data;
    eth = data;
    if ((void *)(eth + 1) + 4 > data_end) {
        return TC_ACT_SHOT;  // Drop if packet is too short
    }

    if (bpf_skb_store_bytes(skb, 0, &header_data, sizeof(header_data), 0) < 0) {
        // load the ethernet header
        return TC_ACT_SHOT;
    }
    __be16 old_type = header_data.h_proto;
    header_data.h_proto = bpf_htons(ETH_P_802_EX1); // Change EtherType to custom value

    // Calculate the offset where the new 4 bytes start (end of original packet)

    // Use bpf_skb_store_bytes to modify the eth_type
    if (bpf_skb_store_bytes(skb, 0, &header_data, sizeof(header_data), BPF_F_RECOMPUTE_CSUM ) < 0){
        bpf_printk("failed to update frame header");
        return TC_ACT_OK;
    }

    __sync_fetch_and_add(seq_num, 1); // TODO: not thread safe
    __u16 counter = (__u16)(__u32)(*seq_num);

    bpf_printk("setting counter: %d %x %x - %d", counter, skb->data, skb->data_end, skb->data_end - skb->data);

    // Write the counter to the new position in the packet
    if (bpf_skb_store_bytes(skb, sizeof(header_data), &counter, sizeof(counter), 0) < 0) {
        return TC_ACT_SHOT; // fail otherwise network state will get poisoned
    }

    // store the frame type with the payload
    if (bpf_skb_store_bytes(skb, sizeof(header_data) + sizeof(counter), &old_type, sizeof(old_type), 0) < 0) {
        bpf_printk("failed to add sequence number");
        return TC_ACT_SHOT; // fail otherwise network state will get poisoned
    }


    bpf_printk("Tagged packet with serial: %d (type: 0x%x -> 0x%x) (size: %d)", *seq_num, old_type, header_data.h_proto, skb->len);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

/*
 To install:
 tc filter add dev bond0 egress basic action bpf obj egress_tag.o sec tc

 uninstall:
 tc filter del dev bond0 egress

 */

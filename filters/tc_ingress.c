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
// ATTACH TO BOND INTERFACE ON INGRESS

// Define a hash map to store recent packet hashes
struct {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512*1024);
		__type(key, __u16);		 // sequence
		__type(value, __u64);	 // timestamp
} seen_packets SEC(".maps");

#define DEDUP_WINDOW_NS 1500000000  // 1.5s // TODO: MAKE THIS CONFIGURABLE

static __always_inline int strip_header(struct __sk_buff *skb, __u32 size, __be16 ether_type) {
    // Clone the packet with redirection, creating a writable clone
    /*
    int new_skb = bpf_clone_redirect(skb, skb->ifindex, 0);
    if (new_skb < 0) {
        bpf_printk("Clone failed");
        return TC_ACT_SHOT;  // Drop the packet if cloning fails
    }

    struct ethhdr header_data;
    if (bpf_skb_load_bytes(new_skb, 0, &header_data, sizeof(header_data)) < 0) {
        // load the ethernet header
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_htons(ETH_P_802_EX1)){
        bpf_printk("ether protocol mismatch - ignoring (0x%x != 0x%x)", eth->h_proto, bpf_htons(ETH_P_802_EX1));
        return TC_ACT_OK;
    }

    header_data.h_proto = ether_type;


    // Adjust the cloned packet to remove the first `size` bytes
    if (bpf_skb_adjust_room(skb, -size, BPF_ADJ_ROOM_MAC, 0) < 0) {
        bpf_printk("Failed to adjust room");
        return TC_ACT_SHOT;  // Drop if unable to adjust
    }

    // Re-fetch data pointers after adjustment
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ensure there's enough room for the remaining MAC header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;  // Drop if packet is too short
    }

    if (bpf_skb_store_bytes(skb, 0, &header_data, sizeof(header_data), 0) < 0) {
        // load the ethernet header
        bpf_printk("Failed to update ethernet header on new frame");
        return TC_ACT_SHOT;
    }
    */
    // Return success to indicate packet is ready to be sent
    return TC_ACT_SHOT;
}

SEC("tc")
int ingress_deduplicate(struct __sk_buff *skb)
{
    if (skb->mark != 0xCAFE) {
        // packet is not coming to us from our slave interfaces, it is coming from
        // the "outside". Do not strip or do anything.
        bpf_printk("non marked packet - this is coming from the outside");
        //return TC_ACT_OK;
    } else {
        bpf_printk("packet is marked - this is coming from the slave interface");
    }

		// Access packet data
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;
    int len = data_end - data;

    // Ensure we have enough room for the Ethernet header + counter
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) + 4 > data_end) {
        return TC_ACT_SHOT;  // Drop if packet is too short
    }

    /*
    if (eth->h_proto != bpf_htons(ETH_P_802_EX1)){
        bpf_printk("ether protocol mismatch - ignoring (0x%x != 0x%x)",
                   eth->h_proto, bpf_htons(ETH_P_802_EX1));
        return TC_ACT_OK;
    }
    */

    // get the sequence number
    __u16 seq_num = 0;
    if (bpf_skb_load_bytes(skb, len - 4, &seq_num, sizeof(seq_num)) < 0) {
        bpf_printk("Can't load sequence");
        return TC_ACT_SHOT;
    }

    // get the original ethernet frame type
    __u16 ether_type = 0;
    if (bpf_skb_load_bytes(skb, len - 2, &ether_type, sizeof(ether_type)) < 0) {
        bpf_printk("Can't load old type");
        return TC_ACT_SHOT;
    }

    int eth_type_offset = offsetof(struct ethhdr, h_proto);
    // Use bpf_skb_store_bytes to modify the eth_type
    if (bpf_skb_store_bytes(skb, eth_type_offset, &ether_type, sizeof(ether_type), 0 ) < 0){
        bpf_printk("failed to update protocol");
        return TC_ACT_OK;
    }

    bpf_printk("Packet sequence and protocol are: %d 0x%x", seq_num, ether_type);

    // Get current timestamp
    __u64 now = bpf_ktime_get_ns();

    // Look up in map
    __u64 *seen = bpf_map_lookup_elem(&seen_packets, &seq_num);
    if (seen){
        // Check if within dedup window
        if (now - *seen < DEDUP_WINDOW_NS) {
            bpf_printk("Dropped duplicate packet (serial: %d)", seq_num);
            return TC_ACT_SHOT;  // Drop duplicate packet
        }
    }

    // Not a duplicate, add to map
    bpf_map_update_elem(&seen_packets, &seq_num, &now, BPF_ANY);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

/*
  install:
  sudo tc filter add dev bond0 ingress basic action bpf obj ingress_strip.o sec tc

  uninstall:
  sudo tc filter del dev bond0 ingress

 */

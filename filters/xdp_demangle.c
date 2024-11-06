#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

#include "xdp_data_access_helpers.h"

//
//                  --- [tap0] -- [nic0]
//                 /
// user -- [bond0] ---- ...
//                 \
//                  --- [tapN] -- [nicN]
//                      ^
//                      |
//                (YOU ARE HERE)
//
// ATTACH TO SLAVE INTERFACE ON INGRESS
//
// this xdp program acts before the network stack ever sees the packet
// it will capture custom ethernet packets coming in on the slave
// interfaces (i.e. over the wire) and strip out the wrapper frame
// restoring the original transmitted packet.
//
// it will append the sequence number to the end of the packet buffer
// which will then immediately be picked up by the tc ingress filter
// and turned into meta data

SEC("xdp")
int xdp_demangle(struct xdp_md *ctx)
{
    // Validate packet bounds
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct custom_header header;

    // Check if the packet has Ethernet header space
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(header) > data_end)
        return XDP_PASS; // non'ya business

    // Copy Ethernet header data
    struct ethhdr new_eth;
    __builtin_memcpy(&header, eth, sizeof(header));

    if(header.eth.h_proto != bpf_htons(ETH_P_802_EX1))
        return XDP_PASS;

    // restore original header location
    __builtin_memcpy(data + sizeof(__u32), &header.eth, sizeof(header.eth));

    // truncate the head of the packet
    if (bpf_xdp_adjust_head(ctx, sizeof(header.data)))
        return XDP_ABORTED;

    // extend the tail of the packet
    if (bpf_xdp_adjust_tail(ctx, sizeof(header.data.sequence)))
        return XDP_ABORTED;

    if (ctx->data_end - ctx->data < 2 )
        return XDP_ABORTED;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = data;
    if ((void *)eth + sizeof(header) > data_end)
        return XDP_PASS; // non'ya business

    // reconvert this packet into its original protocol
    int eth_type_offset = offsetof(struct ethhdr, h_proto);
    if (ctx_store_bytes(ctx, eth_type_offset, &header.data.protocol, sizeof(header.data.protocol), 0) < 0)
        return XDP_ABORTED;

    if (ctx_store_bytes(ctx, data_end - data - 2, &header.data.sequence, 2, 0) < 0)
        return XDP_ABORTED;

    log("[xdp_demangle:%d] demangled frame with sequence number %d (protocol: 0x%0X)",
        ctx->ingress_ifindex, header.data.sequence, header.data.protocol);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

/*
  install:
  sudo ip link set dev tap0 xdp obj /usr/share/fortified_ap/xdp_demangle.o sec xdp
  sudo ip link set dev enp5s0.6 xdp obj ingress_xdp.o sec xdp

  uninstall:
  sudo ip link set dev enp5s0.4 xdp off

 */

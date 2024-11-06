#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
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
// bonded interfaces can't simply be marked using iptables
// this traffic control ebpf program's sole job is to mark
// the packets with tag 0xCFAE, indicating to the bond0 nic
// that this traffic originated from the tunnel side


SEC("tc")
int mark_all_packets(struct __sk_buff *skb)
{
    skb->mark = mark;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";


/*
 To install:

 sudo tc filter add dev tap0 ingress basic action bpf obj /usr/share/fortified_ap/tc_mark.o sec tc

 sudo tc filter add dev enp5s0.4 ingress basic action bpf obj mark_all.o sec tc
 sudo tc filter add dev enp5s0.6 ingress basic action bpf obj mark_all.o sec tc

 uninstall:
 sudo tc filter del dev enp5s0.4 ingress
 sudo tc filter del dev enp5s0.6 ingress

 */

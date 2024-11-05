#!/bin/bash

tc qdisc add dev "$dev" ingress
tc filter add dev "$dev" ingress basic action bpf obj /usr/share/fortified_ap/tc_mark.o sec tc

ip link set dev "$dev" xdp obj /usr/share/fortified_ap/xdp_demangle.o sec xdp

ip link set "$dev" master bond0

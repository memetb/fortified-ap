# Fortified AP

The purpose of this project is to create an AP service on linux that generates all necessary configurations to create a Bound VPN which pools two or more connections to a cloud server and allows clients of the AP to transparently connect to the internet.

The principal requirement is for there to be a *no latency* failover from one network connection to another for the purposes of reliable real-time video conferencing where drop-out and freeze frames are not acceptable.


      [Client0]  -----------\                       /---- VPN1 - NIC1 (e.g. eth0)----\
                            |                      /                                 |
      [Client1]  -----------+-- [ Access-Point ]  |------ VPN2 - NIC2 (e.g. wan0) ---+--> [Server]
                            |                      \                                 |
      [Client2]  -----------/                       \____ VPNX - NICX (e.g. pigeon)--/


# Components #

1. hostapd configuration (including connection and disconnection event monitoring for hooks)
2. ovpn client configurations
3. ovpn server configuration
4. VPS state (IaC and provisioning)
5. systemd service
6. a minimalist web service on http://network that gives current status

See [NETWORKING.md](./NETWORKING.md) for details on layer 3 setup.

# Packet deduplication magic

Quite a bit of effort went into making this work. There are *many* edge conditions/constraints that make it far from trivial to do.

The basic idea is that we can either "figure out" aka "guess" what the duplicate packets are on reception, or we can actively deduplicate them. Figuring out is either a lot of effort or is very naive. A choice was made to actively deduplicate them.


## Deduplication strategy

To deduplicate a packet, we put a sequence number on the ethernet frame prior to it being duplicated by the bonding interface. On the receiving end, we monitor for packets and if the sequence number was seen in the last T duration, we consider it a duplicate and drop it.

This implies that duplicates that arrive very late will incorrectly be identified as new packets.

## What *should* have happened (aka I promise I didn't over-engineer this)


                      traffic marked                             traffic marked
                         [======]                                  [======]
    [origin] ----- [bond0] ---- [nicX] ------ internet ------ [nicX] ---- [bond0] ---- [more places]
                   ^       ^                                              ^
                   |       |                                              |
                   |       |                                      packet is untagged and 
                   |       |                                      duplicates are dropped
                   |       packet is duplicated
                   |       via bonding mode=broadcast
           packet is tagged

In the ideal scenario, there would only be one filter sitting on the bond interface as well as a simple `iptables -j MARK` rule to distinguish traffic between master and slaves, and traffic originating from outside. Depending on the presence or absence of the mark, the packets would either be wrapped with a serial, or unwrapped and deduplicated.

Unfortunately, many limitations along the way prevent it from being this simple (see a Tail (sic) of What-ifs below).

## Implementation details

There are several important (debilitating) constraints imposed on us by the networking stack:

1. `xdp` is very powerful but is essentially not at all integrated with the networking stack: in particular, we are not able to mark packets or pass any meta data
2. furthermore, `xdp` cannot be attached to virtual interfaces (of which bond is one)
3. and finally, attaching XDP filters to each slave interface would require that they now share their state across all nics
4. if using `tc`, packets can only be modified at ingress points (egress modification is not possible by design)
5. resizing of packets using `tc` isn't straightforward: it is easy to grow a packet but isn't always possible to shrink it. This makes encapsulation+decapsulation challenging
6. finally, a packet going from a bond slave to master does not appear as a normal packet and thus, there is no ingress event from when it goes from slave to master. This means that the bonded interface sees exactly what the slave interface saw.

### End to end data flow pictogram (data is flowing from left to right)


    [origin] ----- [bond0] ---- [nicX] ------ internet ------ [nicX] ---- [bond0] ---- [more places]
                   ^  ^                                       ^    ^      ^
                   |  |                                       |    |      |
                   |  |                                       |    |     (d) duplicates are dropped
                   |   \                                      |   (c) packet is marked
                   |    packet is duplicated        (b) tag is stripped
                   |    via bonding mode=broadcast
          (a) packet is tagged

                     
(a) at departure, we simply grow the packet head and add a sequence number + a protocol number (c.f. "But why" 1,2)

(b) on reception on the slave interface on the remote host, we immediately want to reconvert the packet back to its original protocl, strip the sequence + protocol data from the head (c.f. 3) and let the subsequent steps deal with the deduplication by *appending* the sequence number to the end of the packet

(c) mark the packet using tc (c.f. 4, 5)

(d) on ingress of *marked* packets only (c.f. 6) to bond master, do deduplication lookup by popping the sequence number from the last 2 bytes of the frame.


### Individual host filter layout



                     --- [tap0] ---- [nic0]
                    /
    user -- [bond0] ---- ...
                  ^ \
                  |  --- [tapN] ---- [nicN]
                 /       ^      ^
            tc_egress    |      |
           tc_ingress    |  xdp_demangle
                      tc_mark


### Modules

#### `tc_egress`

This is a traffic control egress filter (tc egress) which grows the MAC header by 4 bytes and inserts a 16 bit sequence number and the current packet's protocol id into the packet. The packet is transformed into an `ETH_P_802_EX1` ethernet packet type.

It only acts on packets which are NOT marked, ensuring that only packets egressing from master (`bond0`) toward slave (`tapN`) are mangled.

#### `tc_mark`

This is nothing more than `iptables -t mangle -A PREROUTING -i tap0 -j MARK --set-mark 0xCFAE` except that it works. `iptables` for some reason doesn't play well with openvpn tunnels.

#### `xdp_demangle`

This is a low-level XDP program to unwrap the `ETH_P_802_EX1` packet header and restore the original packet payload. It correctly shrinks the MAC head back to its previous location, and appends a sequence number to the end of the skb buffer.

#### `tc_ingress`

This is the final filter that drops duplicates. tc ingress filter have very few priviledges other than pass or drop. At this stage, the packet that comes to us is in its final state.

Because we also get ingress from the `user->bond0` direction, this filter ignores packets that are not marked `0xCFAE`.

Here we simply take the last 2 bytes of the skb frame - which thanks to `xdp_demangle` will contain the sequence counter tacked on by the sending party's `tc_egress`, and check against an LRU hash that it hasn't yet been seen. If we've seen it before, it's discarded as being a duplicate.

# A tail of "BUT WHY's?"

1. but why must you grow the head?
A: if you simply tack a sequence number to the end of the packet, you have no way of finding where the number is without parsing the packet itself. The packet can go over the wire and get padded with zeros after your sequence number. Thus, you have to put the sequence number *before* the enclosed payload (e.g. IP frame)

2. but why must you change the protocol?
A: if you don't change the protocol and just tack it on, you are liable to get "interpreted" and vanish somewhere along the way by any number of kernel/networking processes on account of being "invalid".

3. but why do an extra step and invoke XDP?
A: because, believe it or not, while growing the head of a packet is easy, shrinking it is not

4. why are you marking the packet?
A: we need to be able to identify whether this packet is coming from `outside->bond->slave` or whether it's going from `slave->bond->outside`. We do this by marking all packets that touch slave. The mark will not get sent on the wire, so if a packet is marked, it can only mean that it is coming from slave to bond.

5. but why not just use `iptables -j MARK`?
A: silly rabbit, that'd be too easy. The answer is you can't.

6. but why only marked?
A: if we apply the deduplication strategy to packets coming from the outside to the bond, we will end up just taking some random last byte number in the packet and assuming it's a sequence number.

Bonus why: why are you doing all of this? Can you not capture the sequence number on ingress (at b) and make it into a meta data?
A: evidently you can't. But you know what, I just learned TAP interfaces don't support XDP so we're fucked.




--------------------



A: on sending the packet, we extend the head of the packet at the sender's bond0 interface, we extend its MAC head and add two integers (one the sequence number, and one the current protocol type). We then modify the protocol of the packet to be a custom packet. This packet then gets broadcast by the bond0 interface.

Q: but why?
A: because appending it to the tail yields unpredictable results
Q: but why?
A: because while a packet may leave our host with 51 bytes of packet size, it might get 0-padded when traversing the wire

--

A: on reception we first rewrite the packet using XDP on ingress
Q: but why?
A: because this is the only time we can modify it
Q: but why?
A: because using `tc` we can only modify a packet on egress and we only have access to the ingress stage of a bonded interface's slave interface
Q: but why?
A: because bonded slave interfaces do not have an egress hook
Q: but why?
A: because we need this packet to be restored to its original shape by the time it gets to the receiving end's bond0 interface
Q: but why?
A: because we can't modify packets (i.e. unmangle them) on ts:ingress
Q: so what?
A: because modifying the packet on egress from bond0 is too late
Q: but why?
A: because some responses (like icmp echo) are handled immediately by the kernel before the bond0's egress event
A: straight to jail. believ'o'not: undercook, overcook. straight to jail

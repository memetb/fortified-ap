# Networking

This is the bog standard vpn tunneling + wifi setup

Network Topology

```
[ Client Devices ] -- (192.168.100.0/24)
          |
          v
[wlan0 - Router - bond0 (Tunnel)]
   192.168.100.1/24    10.10.0.2/24
          |
          v
[ Tunnel (bond0) - Server - eth0 (Internet) ]
      10.10.0.1/24        Public IP
```

## Server

### ip forwarding

```/etc/sysctl.conf

net.ipv4.ip_forward = 1

```

### routing

```
iptables -A FORWARD -i bond0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o bond0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

## Router

### ip forwarding

```/etc/sysctl.conf

net.ipv4.ip_forward = 1

```

### custom routing table

```bash
echo 400 rt_wlan0 >> /etc/iproute2/rt_tables

```

### routes

```
ip route add default via 10.10.0.1 dev bond0 table rt_wlan0
ip rule add from 192.168.100.0/24 table rt_wlan0
```

### iptables

iptables -A FORWARD -i wlan0 -o bond0 -j ACCEPT
iptables -A FORWARD -i bond0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -o bond0 -s 192.168.100.0/24 -j MASQUERADE

### dnsmasq

```/etc/dnsmasq.conf

interface=wlan0
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,8.8.8.8,8.8.4.4

```


### hostapd

``` /etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=HAWTSPAWT
hw_mode=g
channel=7
wmm_enabled=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=AHumblePassword
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

### network

```/etc/network/interfaces

allow-hotplug wlan0
iface wlan0 inet manual
    hostapd /etc/hostapd/hostapd.conf

```


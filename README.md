# Fortified AP

The purpose of this project is to create an AP service on linux that generates all necessary configurations to create a bound VPN which pools two or more connections to a cloud server and allows clients of the AP to transparently connect to the internet.

The principal requirement is for there to be a *no latency* failover from one network connection to another for the purposes of reliable real-time video conferencing where drop-out and freeze frames are not acceptable.


      [Client0]  -----------\                       /---- VPN1 - NIC1 (e.g. eth0)--\
                            |                      /                               |
      [Client1]  -----------+-- [ Access-Point ]  |------ VPN2 - NIC2 (e.g. wan0) -+--> [Server]
                            |                      \                               |
      [Client2]  -----------/                       \____ VPNX - NICX -------------/


## Components

1. host machine AP configuration (including connection and disconnection event monitoring for hooks)
2. generate VPN configurations for access point to Server connection
3. generate Server VPN configuration
4. manage VPS state (IaC and provisioning)
5. package the whole thing into a systemd service

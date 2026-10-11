#!/bin/bash
# usage: client.sh IF_A IF_D
IF_A=$1
IF_D=$2

#...............................................Addresses, then bring interfaces up.................................................
ip addr add 10.10.1.10/24 dev "$IF_A"
ip addr add 10.10.4.2/30 dev "$IF_D"
ip link set dev "$IF_A" up
ip link set dev "$IF_D" up

#................................................Host, not a router (A4)...........................................................
sysctl -w net.ipv4.ip_forward=0

#.....................................LANs B and C via r1 (A1, A2). Link D is directly connected to r2...................................
ip route add 10.10.2.0/24 via 10.10.1.1
ip route add 10.10.3.0/24 via 10.10.1.1

#..............................Replies from the server arrive on Link D but the route back to the server...........................
#..............................goes via LAN A, so strict rp_filter would drop them. Loose (2) on IF_D only.............................
sysctl -w net.ipv4.conf."$IF_D".rp_filter=2
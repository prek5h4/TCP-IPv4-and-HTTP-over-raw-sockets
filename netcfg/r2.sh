#!/bin/bash
# usage: r2.sh IF_B IF_C IF_D
IF_B=$1
IF_C=$2
IF_D=$3

ip addr add 10.10.2.2/24 dev "$IF_B"
ip addr add 10.10.3.1/24 dev "$IF_C"
ip addr add 10.10.4.1/30 dev "$IF_D"
ip link set dev "$IF_B" up
ip link set dev "$IF_C" up
ip link set dev "$IF_D" up

#.......................................................Router(A4)...........................................................
sysctl -w net.ipv4.ip_forward=1

#.......................LAN A via r1, client's own address via Link D..................................
#.......................................................No default route(A6).................................................
ip route add 10.10.1.0/24 via 10.10.2.1
ip route add 10.10.1.10/32 via 10.10.4.2

#.......................Client traffic arrives on LAN B (via r1) but r2's route back to the client.................................
sysctl -w net.ipv4.conf."$IF_B".rp_filter=2
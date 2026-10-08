#!/bin/bash
# usage: server.sh IF_C
IF_C=$1

ip addr add 10.10.3.10/24 dev "$IF_C"
ip link set dev "$IF_C" up

# Host, not a router (A4)
sysctl -w net.ipv4.ip_forward=0

# Everything else via r2 (A3: replies go to r2, which sends them over Link D)
ip route add default via 10.10.3.1

# rp_filter left strict (A7)
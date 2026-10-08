#!/bin/bash
# usage: r1.sh IF_A IF_B
IF_A=$1
IF_B=$2

ip addr add 10.10.1.1/24 dev "$IF_A"
ip addr add 10.10.2.1/24 dev "$IF_B"
ip link set dev "$IF_A" up
ip link set dev "$IF_B" up

# Router (A4)
sysctl -w net.ipv4.ip_forward=1

# One route for every network r1 is not attached to (A5)
ip route add default via 10.10.2.2

# rp_filter left strict (A7)
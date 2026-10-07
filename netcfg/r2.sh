#!/bin/bash
IF_B=$1
IF_C=$2
IF_D=$3

ip addr add 10.10.2.2/24 dev $IF_B
ip addr add 10.10.3.1/24 dev $IF_C
ip addr add 10.10.4.1/30 dev $IF_D
ip link set dev $IF_B up
ip link set dev $IF_C up
ip link set dev $IF_D up

# Enable packet forwarding
sysctl -w net.ipv4.ip_forward=1

# Explicit route to LAN A via r1
ip route add 10.10.1.0/24 via 10.10.2.1

# Specific host route to send packets to client via Link D
ip route add 10.10.1.10/32 via 10.10.4.2

# Relax rp_filter for asymmetric routing
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.$IF_B.rp_filter=0
sysctl -w net.ipv4.conf.$IF_C.rp_filter=0
sysctl -w net.ipv4.conf.$IF_D.rp_filter=0
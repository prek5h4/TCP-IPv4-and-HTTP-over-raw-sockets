#!/bin/bash
IF_A=$1
IF_D=$2

# Assign IP addresses and bring interfaces up
ip addr add 10.10.1.10/24 dev $IF_A
ip addr add 10.10.4.2/30 dev $IF_D
ip link set dev $IF_A up
ip link set dev $IF_D up

# Route to server via r1's LAN A interface
ip route add 10.10.3.0/24 via 10.10.1.1

# Relax rp_filter for asymmetric routing
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.$IF_A.rp_filter=0
sysctl -w net.ipv4.conf.$IF_D.rp_filter=0
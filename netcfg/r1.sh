#!/bin/bash
IF_A=$1
IF_B=$2

ip addr add 10.10.1.1/24 dev $IF_A
ip addr add 10.10.2.1/24 dev $IF_B
ip link set dev $IF_A up
ip link set dev $IF_B up

# Enable packet forwarding for the router
sysctl -w net.ipv4.ip_forward=1

# Single default route to reach everything else via r2
ip route add default via 10.10.2.2
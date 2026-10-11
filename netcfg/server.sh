#!/bin/bash
# usage: server.sh IF_C
IF_C=$1

ip addr add 10.10.3.10/24 dev "$IF_C"
ip link set dev "$IF_C" up

#..............................................Host.........................................................
sysctl -w net.ipv4.ip_forward=0

#.......................................Everything else via r2...................................
ip route add default via 10.10.3.1


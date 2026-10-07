#!/bin/bash
IF_C=$1

ip addr add 10.10.3.10/24 dev $IF_C
ip link set dev $IF_C up

# Route replies back via r2
ip route add default via 10.10.3.1
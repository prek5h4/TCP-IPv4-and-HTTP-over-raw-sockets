#!/bin/bash
# TESTING HELPER ONLY - not part of the submission. Delete before zipping.
# usage: sudo bash /mnt/share/go.sh client|r1|r2|server
# Sets strict rp_filter everywhere, finds interface names by MAC,
# runs the matching script from the same folder, then shows the result.

D=$(dirname "$(readlink -f "$0")")

# name of the interface whose MAC is 52:54:00:<suffix>
mac() { ip -br link | awk -v m="52:54:00:$1" '$3==m {print $1}'; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo bash $0 $1"; exit 1
fi

for i in all default $(ls /sys/class/net); do
    sysctl -w net.ipv4.conf.$i.rp_filter=1 > /dev/null
done

case "$1" in
    client) N="$(mac 01:00:01) $(mac 01:00:02)"; EXPECT=2 ;;
    r1)     N="$(mac 02:00:01) $(mac 02:00:02)"; EXPECT=2 ;;
    r2)     N="$(mac 03:00:01) $(mac 03:00:02) $(mac 03:00:03)"; EXPECT=3 ;;
    server) N="$(mac 04:00:01)"; EXPECT=1 ;;
    *) echo "usage: sudo bash $0 client|r1|r2|server"; exit 1 ;;
esac

# every name must be found, and all must differ
if [ "$(echo $N | wc -w)" -ne "$EXPECT" ] || [ "$(echo $N | tr ' ' '\n' | sort -u | wc -l)" -ne "$EXPECT" ]; then
    echo "Could not match all interfaces by MAC (got: '$N'). Not running."
    ip -br link
    exit 1
fi

echo "Running $1.sh with: $N"
bash "$D/$1.sh" $N
echo
ip -br addr
echo
ip route

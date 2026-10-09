#!/bin/bash
# TESTING HELPER ONLY - not part of the submission.
# One command: capture + run your client + compare with curl.
# usage: sudo bash t.sh [FILE] [SERVER_IP] [PORT]     (run on the CLIENT VM)
# defaults: test.txt 10.10.3.10 8080
# Works from any folder: it looks for client/run-client next to this script
# (project root) or one level above it (if this script sits in tools/).

F=${1:-test.txt}; F=${F#/}
H=${2:-10.10.3.10}
PORT=${3:-8080}
URL="http://$H:$PORT/$F"

D="$(dirname "$(readlink -f "$0")")"
R=""
for c in "$D" "$D/.." "/mnt/share"; do
    if [ -f "$c/client/run-client" ]; then R="$(readlink -f "$c")"; break; fi
done
if [ -z "$R" ]; then
    echo "Cannot find client/run-client (looked in $D, $D/.., /mnt/share)"; exit 1
fi

if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo"; exit 1; fi

rm -f /tmp/cap.pcap /tmp/output /tmp/client.log

tcpdump -nn -i any tcp port "$PORT" -w /tmp/cap.pcap 2>/dev/null &
TP=$!
sleep 1

echo "== running client from $R: $URL"
sh "$R/client/run-client" "$URL" -o /tmp/output --log /tmp/client.log
RC=$?
sleep 1
kill $TP 2>/dev/null; wait $TP 2>/dev/null

echo
echo "exit code : $RC"
if [ -f /tmp/output ]; then
    echo "mine  md5 : $(md5sum < /tmp/output | cut -d' ' -f1)"
else
    echo "mine  md5 : (no output file)"
fi
echo "curl  md5 : $(curl -s "$URL" | md5sum | cut -d' ' -f1)"
if [ -f /tmp/client.log ]; then
    echo "log lines : $(wc -l < /tmp/client.log)"
else
    echo "log lines : (no log file)"
fi
echo "files     : /tmp/output  /tmp/client.log  /tmp/cap.pcap"
echo
echo "== capture (first 40 packets)"
tcpdump -nn -r /tmp/cap.pcap 2>/dev/null | head -n 40

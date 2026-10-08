"""
check_log.py - TESTING TOOL ONLY (do not submit). Validates a --log file.

Usage:  python3 tools/check_log.py client.log

WHAT TO CHECK per line (see section 2.6 / Table 3):
    * matches the exact format with single spaces (use one compiled regex):
      DIR SRC:SPORT > DST:DPORT ttl=T id=I seq=S ack=A flags=0xFF win=W len=L mss=M
    * DIR is SEND or RECV; flags is 0x + exactly two lowercase hex digits
    * seq/ack are in 0..2**32-1; win is in 0..65535; mss is a number or '-'
    * SEND lines: id != 0, and mss is 1460 on SYN / SYN-ACK and '-' otherwise
    * len never exceeds 1460
SUMMARY to print: number of SEND/RECV lines, number of retransmissions
    (a SEND repeating an earlier seq with len>0, or a repeated SYN), and the
    first line that fails with its line number.
"""
import re
import sys


LINE_RE = None  # TODO: compile the regex described in the header


def check_line(line: str, lineno: int) -> list:
    """Return a list of problem strings for this line (empty list = OK)."""
    raise NotImplementedError


def main(path: str) -> int:
    """Read the file, check every line, print problems and a summary.
    Return 0 if all lines pass, 1 otherwise."""
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

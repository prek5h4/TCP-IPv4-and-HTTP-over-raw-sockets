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

LINE_RE = re.compile(
    r"^(SEND|RECV) (\d{1,3}(?:\.\d{1,3}){3}):(\d+) > (\d{1,3}(?:\.\d{1,3}){3}):(\d+) "
    r"ttl=(\d+) id=(\d+) seq=(\d+) ack=(\d+) flags=0x([0-9a-f]{2}) win=(\d+) len=(\d+) mss=(-|\d+)$"
)


def check_line(line: str, lineno: int) -> list:
    """Return a list of problem strings for this line (empty list = OK)."""
    problems = []
    line = line.rstrip("\r\n")
    m = LINE_RE.match(line)
    if not m:
        problems.append(f"Line {lineno}: does not match expected format")
        return problems

    direction, src_ip, sport, dst_ip, dport, ttl, ident, seq, ack, flags_hex, win, length, mss = m.groups()

    sport, dport = int(sport), int(dport)
    ttl, ident = int(ttl), int(ident)
    seq, ack = int(seq), int(ack)
    flags = int(flags_hex, 16)
    win, length = int(win), int(length)

    if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
        problems.append(f"Line {lineno}: invalid ports ({sport}, {dport})")
    if not (0 <= seq < 2**32 and 0 <= ack < 2**32):
        problems.append(f"Line {lineno}: seq/ack out of range ({seq}, {ack})")
    if not (0 <= win <= 65535):
        problems.append(f"Line {lineno}: win out of range ({win})")
    if length > 1460:
        problems.append(f"Line {lineno}: payload length {length} exceeds 1460")

    if direction == "SEND":
        if ident == 0:
            problems.append(f"Line {lineno}: SEND id must be non-zero")
        is_syn = bool(flags & 0x02)
        if is_syn:
            if mss != "1460":
                problems.append(f"Line {lineno}: SEND SYN must have mss=1460, got {mss}")
        else:
            if mss != "-":
                problems.append(f"Line {lineno}: SEND non-SYN must have mss=-, got {mss}")

    return problems


def main(path: str) -> int:
    """Read the file, check every line, print problems and a summary.
    Return 0 if all lines pass, 1 otherwise."""
    send_count = 0
    recv_count = 0
    retransmissions = 0
    first_failure = None
    all_problems = []

    seen_sends = set()

    with open(path, "r") as f:
        for lineno, line in enumerate(f, 1):
            line_str = line.rstrip("\r\n")
            if not line_str:
                continue
            probs = check_line(line_str, lineno)
            if probs:
                if first_failure is None:
                    first_failure = (lineno, line_str, probs)
                all_problems.extend(probs)

            m = LINE_RE.match(line_str)
            if m:
                direction, _, _, _, _, _, _, seq, _, flags_hex, _, length, _ = m.groups()
                seq_val = int(seq)
                len_val = int(length)
                flags_val = int(flags_hex, 16)
                if direction == "SEND":
                    send_count += 1
                    is_syn = bool(flags_val & 0x02)
                    if (seq_val, len_val > 0 or is_syn) in seen_sends and (len_val > 0 or is_syn):
                        retransmissions += 1
                    else:
                        seen_sends.add((seq_val, len_val > 0 or is_syn))
                else:
                    recv_count += 1

    print(f"Summary for {path}:")
    print(f"  SEND lines: {send_count}")
    print(f"  RECV lines: {recv_count}")
    print(f"  Retransmissions: {retransmissions}")

    if all_problems:
        print(f"\nFound {len(all_problems)} problems:")
        for p in all_problems[:10]:
            print(f"  {p}")
        if len(all_problems) > 10:
            print(f"  ... and {len(all_problems) - 10} more")
        print(f"\nFirst failure: line {first_failure[0]}: {first_failure[1]}")
        return 1
    else:
        print("  All lines PASSED!")
        return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_log.py <logfile>")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))

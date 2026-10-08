"""
pktlog.py - the packet log written with --log FILE.                    (section 2.6)

ROLE
    One place that formats and writes the log, so both the client and server
    produce identical lines. If no --log was given, every method is a no-op,
    so callers never need an "if logging" check.

WHEN TO LOG
    SEND : every TCP segment you transmit - SYN, SYN-ACK, data, retransmissions,
           pure ACKs, FINs, RSTs. Values are what you PUT in the packet.
    RECV : only segments you ACCEPT: they belong to your connection AND passed
           both the IP and TCP checksums. Values are what you PARSED. Dropped
           packets are never logged.

LINE FORMAT (single spaces, exactly):
    DIR SRC_IP:SPORT > DST_IP:DPORT ttl=T id=I seq=S ack=A flags=0xFF win=W len=L mss=M
    DIR    SEND or RECV
    ttl,id decimal, from the IPv4 header
    seq,ack raw unsigned 32-bit, NOT relative; print ack even when ACK flag is off
    flags  byte 13 of the TCP header as 0x + two lowercase hex digits (SYN 0x02, SYN-ACK 0x12)
    win    raw 16-bit window field
    len    TCP payload length in bytes
    mss    MSS option value, or "-" if there is none
    Flush after EVERY line (a crash must not lose the log).

EXAMPLE
    SEND 10.10.1.10:62425 > 10.10.3.10:8000 ttl=64 id=301 seq=1000 ack=0 flags=0x02 win=65535 len=0 mss=1460
"""
from typing import Optional


class PacketLogger:
    def __init__(self, path: Optional[str]) -> None:
        """Open `path` for writing (truncate) if it is not None; otherwise
        remember that logging is off."""
        raise NotImplementedError

    def log_send(self, src: str, sport: int, dst: str, dport: int, ttl: int,
                 ident: int, seq: int, ack: int, flags: int, win: int,
                 length: int, mss: Optional[int]) -> None:
        """Format and write a SEND line."""
        raise NotImplementedError

    def log_recv(self, src: str, sport: int, dst: str, dport: int, ttl: int,
                 ident: int, seq: int, ack: int, flags: int, win: int,
                 length: int, mss: Optional[int]) -> None:
        """Format and write a RECV line."""
        raise NotImplementedError

    def _format(self, direction: str, src: str, sport: int, dst: str,
                dport: int, ttl: int, ident: int, seq: int, ack: int,
                flags: int, win: int, length: int, mss: Optional[int]) -> str:
        """Return the line described in the module header (no newline).
        Watch: seq/ack unsigned, flags '0x%02x', mss '-' when None."""
        raise NotImplementedError

    def _write(self, line: str) -> None:
        """Write line + newline and flush immediately."""
        raise NotImplementedError

    def close(self) -> None:
        """Close the file (if open)."""
        raise NotImplementedError

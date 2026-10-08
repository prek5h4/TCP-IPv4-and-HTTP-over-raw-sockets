"""
packet.py - build, parse and checksum IPv4 + TCP packets.            (T1, T2, T3, T4)

ROLE
    Pure functions and two small dataclasses. No sockets, no timers, no global
    state, so everything here can be unit-tested on your Mac without the VMs.
    Everything above this layer (tcp.py) talks in "src, dst, ports, seq, ack,
    flags, payload" and never touches raw bytes.

IPv4 HEADER (20 bytes, no options; all fields big-endian / network order)
    byte 0     : version(4 bits)=4 | IHL(4 bits)=5   (header length in 32-bit words)
    byte 1     : TOS = 0
    bytes 2-3  : total length = 20 + len(tcp segment)
    bytes 4-5  : identification (must be NON-ZERO, T1)
    bytes 6-7  : flags(3 bits) | fragment offset(13 bits). DF=0x4000 is fine.
    byte 8     : TTL (64)
    byte 9     : protocol = 6 (TCP)
    bytes 10-11: header checksum (compute with this field set to 0 first)
    bytes 12-15: source address     (socket.inet_aton)
    bytes 16-19: destination address

TCP HEADER (20 bytes + options)
    bytes 0-1  : source port
    bytes 2-3  : destination port
    bytes 4-7  : sequence number (32-bit, wraps)
    bytes 8-11 : acknowledgment number (32-bit)
    byte 12    : data offset (high 4 bits, header length in 32-bit words) | 0 reserved
    byte 13    : flags  (FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10)
    bytes 14-15: window
    bytes 16-17: checksum (computed over pseudo-header + header + payload)
    bytes 18-19: urgent pointer = 0
    options    : only the MSS option on SYN / SYN-ACK:  kind=2, len=4, value(2 bytes)
                 -> header becomes 24 bytes, so data offset = 6.

TCP CHECKSUM PSEUDO-HEADER (prepended ONLY for the checksum, never sent)
    src ip (4) | dst ip (4) | zero (1) | protocol=6 (1) | tcp length (2)
    where "tcp length" = TCP header + options + payload.

INTERNET CHECKSUM (RFC 1071), used by both IP and TCP
    Treat the data as 16-bit big-endian words (pad one zero byte if odd length),
    add them all up, fold any carry above bit 15 back in until it fits in 16
    bits, then take the ones' complement. When you checksum a block that already
    contains a correct checksum, the result is 0 - that is how receivers verify.

TESTING TIPS
    * Check the RFC 1071 worked example, and a hand-made packet from tcpdump -x.
    * Build -> parse round trip must return the original fields.
    * Flip one byte of a built packet: parsing must return None.
    * Send a real SYN and look at it with `tcpdump -nn -v`: no "bad cksum".
"""
from dataclasses import dataclass
from typing import Optional

# TCP flag bits (byte 13 of the TCP header)
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
DEFAULT_MSS = 1460


@dataclass
class IPInfo:
    """What you need from a parsed IPv4 header (plus the TCP bytes inside it)."""
    src: str            # dotted-quad string
    dst: str
    ttl: int            # logged as ttl=
    ident: int          # logged as id=
    payload: bytes      # everything after the IP header = the TCP segment


@dataclass
class TCPSeg:
    """A parsed TCP segment. Raw values, exactly as on the wire (for the log)."""
    sport: int
    dport: int
    seq: int            # raw unsigned 32-bit
    ack: int            # raw unsigned 32-bit (log it even if the ACK flag is off)
    flags: int          # byte 13
    window: int         # raw 16-bit field
    mss: Optional[int]  # value of the MSS option, or None if absent
    payload: bytes


def internet_checksum(data: bytes) -> int:
    """RFC 1071 checksum of `data` (see module header). Returns a 16-bit int.
    Used for the IP header checksum and, via tcp_checksum(), the TCP checksum.
    Must handle odd-length data (pad with a zero byte, do not modify caller's data)."""
    raise NotImplementedError


def tcp_checksum(src: str, dst: str, tcp_bytes: bytes) -> int:
    """Checksum of pseudo-header + tcp_bytes. When BUILDING, tcp_bytes has its
    checksum field zeroed. When VERIFYING a received segment, tcp_bytes still
    contains the sender's checksum and a valid packet yields 0."""
    raise NotImplementedError


def build_ip_header(src: str, dst: str, payload_len: int, ident: int, ttl: int = 64) -> bytes:
    """Return the 20-byte IPv4 header for a TCP segment of `payload_len` bytes
    (payload_len = TCP header + options + data). Fill every field listed in the
    module header and compute the header checksum last. ident must be non-zero."""
    raise NotImplementedError


def build_tcp_segment(src: str, dst: str, sport: int, dport: int,
                      seq: int, ack: int, flags: int, window: int,
                      payload: bytes = b"", mss: Optional[int] = None) -> bytes:
    """Return the TCP header (+ MSS option if mss is not None) + payload with a
    correct checksum. seq/ack are masked to 32 bits so callers can pass sums
    that overflowed. Data offset must reflect the 24-byte header when the MSS
    option is present. Only the MSS option may ever be added (T3)."""
    raise NotImplementedError


def build_packet(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
                 flags: int, window: int, ident: int, payload: bytes = b"",
                 mss: Optional[int] = None, ttl: int = 64) -> bytes:
    """Convenience: build_tcp_segment() then prepend build_ip_header().
    Returns the full IP packet ready for the raw socket."""
    raise NotImplementedError


def parse_ip_packet(raw: bytes) -> Optional[IPInfo]:
    """Parse what a raw socket returned (it INCLUDES the IP header). Return None
    (i.e. drop silently) if: shorter than 20 bytes, version != 4, protocol != 6,
    IHL < 5, header checksum invalid, or total length is larger than len(raw).
    Use the IHL field to find where the payload starts (do not assume 20) and
    cut the payload at total length (ignore any trailing padding)."""
    raise NotImplementedError


def parse_tcp_segment(ip: IPInfo) -> Optional[TCPSeg]:
    """Parse ip.payload as TCP. Return None if too short, data offset invalid,
    or the TCP checksum (with pseudo-header from ip.src / ip.dst) is bad (T4).
    Read options with parse_tcp_options(); payload starts at data_offset*4."""
    raise NotImplementedError


def parse_tcp_options(opts: bytes) -> Optional[int]:
    """Walk the option bytes and return the MSS value, or None if absent.
    Layout: kind 0 = end of list, kind 1 = single-byte NOP, otherwise
    kind | length | data (length includes the 2 header bytes). Ignore every kind
    except 2 (MSS). Stop (do not crash) if length < 2 or it runs past the end."""
    raise NotImplementedError


def new_ip_id() -> int:
    """Next IPv4 identification value: a counter that wraps at 65535 and never
    returns 0 (T1). Starting at a random value is fine."""
    raise NotImplementedError

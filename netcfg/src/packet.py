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
import random
import socket
import struct
from typing import Optional

# TCP flag bits (byte 13 of the TCP header)
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
DEFAULT_MSS = 1460

_ip_id_counter = random.randint(1, 65535)


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
    if len(data) % 2 != 0:
        data = data + b"\x00"

    s = sum(struct.unpack(f"!{len(data) // 2}H", data))

    while (s >> 16) > 0:
        s = (s & 0xffff) + (s >> 16)

    return (~s) & 0xffff


def tcp_checksum(src: str, dst: str, tcp_bytes: bytes) -> int:
    """Checksum of pseudo-header + tcp_bytes. When BUILDING, tcp_bytes has its
    checksum field zeroed. When VERIFYING a received segment, tcp_bytes still
    contains the sender's checksum and a valid packet yields 0."""
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    placeholder = 0
    protocol = socket.IPPROTO_TCP  # 6
    tcp_len = len(tcp_bytes)
    pseudo_header = struct.pack("!4s4sBBH", src_bytes, dst_bytes, placeholder, protocol, tcp_len)
    return internet_checksum(pseudo_header + tcp_bytes)


def build_ip_header(src: str, dst: str, payload_len: int, ident: int, ttl: int = 64) -> bytes:
    """Return the 20-byte IPv4 header for a TCP segment of `payload_len` bytes
    (payload_len = TCP header + options + data). Fill every field listed in the
    module header and compute the header checksum last. ident must be non-zero."""
    if ident == 0:
        ident = new_ip_id()
    version_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    tot_len = 20 + payload_len
    flags_frag = 0x4000  # DF flag set, fragment offset 0
    proto = socket.IPPROTO_TCP  # 6
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)

    hdr_zero = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, tot_len, ident, flags_frag, ttl, proto, 0, src_bytes, dst_bytes)
    cksum = internet_checksum(hdr_zero)
    return struct.pack("!BBHHHBBH4s4s", version_ihl, tos, tot_len, ident, flags_frag, ttl, proto, cksum, src_bytes, dst_bytes)


def build_tcp_segment(src: str, dst: str, sport: int, dport: int,
                      seq: int, ack: int, flags: int, window: int,
                      payload: bytes = b"", mss: Optional[int] = None) -> bytes:
    """Return the TCP header (+ MSS option if mss is not None) + payload with a
    correct checksum. seq/ack are masked to 32 bits so callers can pass sums
    that overflowed. Data offset must reflect the 24-byte header when the MSS
    option is present. Only the MSS option may ever be added (T3)."""
    seq = seq & 0xffffffff
    ack = ack & 0xffffffff
    window = window & 0xffff

    if mss is not None:
        opts = struct.pack("!BBH", 2, 4, mss)
        data_offset = 6  # 24 bytes / 4 = 6
    else:
        opts = b""
        data_offset = 5  # 20 bytes / 4 = 5

    data_offset_res = (data_offset << 4) & 0xf0
    urg_ptr = 0

    tcp_hdr_zero = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset_res, flags, window, 0, urg_ptr) + opts
    cksum = tcp_checksum(src, dst, tcp_hdr_zero + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset_res, flags, window, cksum, urg_ptr) + opts
    return tcp_hdr + payload


def build_packet(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
                 flags: int, window: int, ident: int, payload: bytes = b"",
                 mss: Optional[int] = None, ttl: int = 64) -> bytes:
    """Convenience: build_tcp_segment() then prepend build_ip_header().
    Returns the full IP packet ready for the raw socket."""
    tcp_seg = build_tcp_segment(src, dst, sport, dport, seq, ack, flags, window, payload, mss)
    ip_hdr = build_ip_header(src, dst, len(tcp_seg), ident, ttl)
    return ip_hdr + tcp_seg


def parse_ip_packet(raw: bytes) -> Optional[IPInfo]:
    """Parse what a raw socket returned (it INCLUDES the IP header). Return None
    (i.e. drop silently) if: shorter than 20 bytes, version != 4, protocol != 6,
    IHL < 5, header checksum invalid, or total length is larger than len(raw).
    Use the IHL field to find where the payload starts (do not assume 20) and
    cut the payload at total length (ignore any trailing padding)."""
    if len(raw) < 20:
        return None
    v_ihl = raw[0]
    version = v_ihl >> 4
    ihl = v_ihl & 0x0f
    if version != 4 or ihl < 5:
        return None
    ihl_bytes = ihl * 4
    if len(raw) < ihl_bytes:
        return None
    tot_len = struct.unpack("!H", raw[2:4])[0]
    if len(raw) < tot_len or tot_len < ihl_bytes:
        return None
    proto = raw[9]
    if proto != 6:  # IPPROTO_TCP
        return None
    if internet_checksum(raw[:ihl_bytes]) != 0:
        return None

    ident = struct.unpack("!H", raw[4:6])[0]
    ttl = raw[8]
    src = socket.inet_ntoa(raw[12:16])
    dst = socket.inet_ntoa(raw[16:20])
    payload = raw[ihl_bytes:tot_len]
    return IPInfo(src=src, dst=dst, ttl=ttl, ident=ident, payload=payload)


def parse_tcp_options(opts: bytes) -> Optional[int]:
    """Walk the option bytes and return the MSS value, or None if absent.
    Layout: kind 0 = end of list, kind 1 = single-byte NOP, otherwise
    kind | length | data (length includes the 2 header bytes). Ignore every kind
    except 2 (MSS). Stop (do not crash) if length < 2 or it runs past the end."""
    i = 0
    mss = None
    while i < len(opts):
        kind = opts[i]
        if kind == 0:  # End of Option List
            break
        elif kind == 1:  # No-Operation (NOP)
            i += 1
            continue
        else:
            if i + 1 >= len(opts):
                break
            opt_len = opts[i + 1]
            if opt_len < 2 or i + opt_len > len(opts):
                break
            if kind == 2 and opt_len == 4:
                mss = struct.unpack("!H", opts[i + 2:i + 4])[0]
            i += opt_len
    return mss


def parse_tcp_segment(ip: IPInfo) -> Optional[TCPSeg]:
    """Parse ip.payload as TCP. Return None if too short, data offset invalid,
    or the TCP checksum (with pseudo-header from ip.src / ip.dst) is bad (T4).
    Read options with parse_tcp_options(); payload starts at data_offset*4."""
    data = ip.payload
    if len(data) < 20:
        return None
    data_offset = (data[12] >> 4) & 0x0f
    header_len = data_offset * 4
    if data_offset < 5 or len(data) < header_len:
        return None
    if tcp_checksum(ip.src, ip.dst, data) != 0:
        return None

    sport, dport, seq, ack = struct.unpack("!HHII", data[0:12])
    flags = data[13]
    window = struct.unpack("!H", data[14:16])[0]
    opts = data[20:header_len]
    mss = parse_tcp_options(opts)
    payload = data[header_len:]
    return TCPSeg(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=window, mss=mss, payload=payload)


def new_ip_id() -> int:
    """Next IPv4 identification value: a counter that wraps at 65535 and never
    returns 0 (T1). Starting at a random value is fine."""
    global _ip_id_counter
    val = _ip_id_counter
    _ip_id_counter += 1
    if _ip_id_counter > 65535:
        _ip_id_counter = 1
    return val

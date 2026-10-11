#................................................imports...........................................
import random                                                                   #for random initial ip identifier
import socket                                                                   #for ip address conversion functions
import struct                                                                   #for packing and unpacking binary headers
from dataclasses import dataclass                                               #for data classes
from typing import Optional                                                     #for typing

#...............................................tcp flags.........................................
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10                         
DEFAULT_MSS = 1460                                                              #default maximum segment size

_ip_id_counter = random.randint(1, 65535)                                       #starting ip id counter non-zero


#.............................................ip info container...................................
@dataclass
class IPInfo:
    src: str                                                                    #source ip string
    dst: str                                                                    #destination ip string
    ttl: int                                                                    #time to live
    ident: int                                                                  #ip identification field
    payload: bytes                                                              #tcp segment payload


#............................................tcp segment container................................
@dataclass
class TCPSeg:
    sport: int                                                                  #source port
    dport: int                                                                  #destination port
    seq: int                                                                    #sequence number
    ack: int                                                                    #acknowledgment number
    flags: int                                                                  #flags byte
    window: int                                                                 #receive window size
    mss: Optional[int]                                                          #parsed mss option if present
    payload: bytes                                                              #application payload


#........................................internet checksum rfc 1071...............................
def internet_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data = data + b"\x00"                                                   #padding odd byte with zero

    s = sum(struct.unpack(f"!{len(data) // 2}H", data))                         #summing 16-bit words

    while (s >> 16) > 0:
        s = (s & 0xffff) + (s >> 16)                                            #folding 32-bit carry into 16 bits

    return (~s) & 0xffff                                                        #ones complement


#..........................................tcp checksum helper....................................
def tcp_checksum(src: str, dst: str, tcp_bytes: bytes) -> int:
    src_bytes = socket.inet_aton(src)                                           #4 bytes source ip
    dst_bytes = socket.inet_aton(dst)                                           #4 bytes destination ip
    placeholder = 0                                                             #reserved zero byte
    protocol = socket.IPPROTO_TCP                                               #protocol 6 (tcp)
    tcp_len = len(tcp_bytes)                                                    #tcp segment length
    pseudo_header = struct.pack("!4s4sBBH", src_bytes, dst_bytes, placeholder, protocol, tcp_len)
    return internet_checksum(pseudo_header + tcp_bytes)


#.........................................build ipv4 header.......................................
def build_ip_header(src: str, dst: str, payload_len: int, ident: int, ttl: int = 64) -> bytes:
    if ident == 0:
        ident = new_ip_id()
    version_ihl = (4 << 4) | 5                                                  #version 4, ihl 5 (20 bytes)
    tos = 0
    tot_len = 20 + payload_len                                                  #total ip packet length
    flags_frag = 0x4000                                                         #df flag set (do not fragment)
    proto = socket.IPPROTO_TCP                                                  #tcp protocol number 6
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)

    hdr_zero = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, tot_len, ident, flags_frag, ttl, proto, 0, src_bytes, dst_bytes)
    cksum = internet_checksum(hdr_zero)
    return struct.pack("!BBHHHBBH4s4s", version_ihl, tos, tot_len, ident, flags_frag, ttl, proto, cksum, src_bytes, dst_bytes)


#........................................build tcp segment........................................
def build_tcp_segment(src: str, dst: str, sport: int, dport: int,
                      seq: int, ack: int, flags: int, window: int,
                      payload: bytes = b"", mss: Optional[int] = None) -> bytes:
    seq = seq & 0xffffffff                                                      #masking to 32 bits
    ack = ack & 0xffffffff                                                      #masking to 32 bits
    window = window & 0xffff                                                    #masking to 16 bits

    if mss is not None:
        opts = struct.pack("!BBH", 2, 4, mss)                                   #mss option: kind 2, len 4, value
        data_offset = 6                                                         #24 bytes header (offset 6)
    else:
        opts = b""
        data_offset = 5                                                         #20 bytes header (offset 5)

    data_offset_res = (data_offset << 4) & 0xf0
    urg_ptr = 0

    tcp_hdr_zero = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset_res, flags, window, 0, urg_ptr) + opts
    cksum = tcp_checksum(src, dst, tcp_hdr_zero + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset_res, flags, window, cksum, urg_ptr) + opts
    return tcp_hdr + payload


#.........................................build full packet.......................................
def build_packet(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
                 flags: int, window: int, ident: int, payload: bytes = b"",
                 mss: Optional[int] = None, ttl: int = 64) -> bytes:
    tcp_seg = build_tcp_segment(src, dst, sport, dport, seq, ack, flags, window, payload, mss)
    ip_hdr = build_ip_header(src, dst, len(tcp_seg), ident, ttl)
    return ip_hdr + tcp_seg


#.........................................parse ipv4 packet.......................................
def parse_ip_packet(raw: bytes) -> Optional[IPInfo]:
    if len(raw) < 20:                                                           #minimum ip header size
        return None
    v_ihl = raw[0]
    version = v_ihl >> 4
    ihl = v_ihl & 0x0f
    if version != 4 or ihl < 5:                                                 #ipv4 and minimum ihl 5
        return None
    ihl_bytes = ihl * 4
    if len(raw) < ihl_bytes:
        return None
    tot_len = struct.unpack("!H", raw[2:4])[0]                                  #ip total length
    if len(raw) < tot_len or tot_len < ihl_bytes:
        return None
    proto = raw[9]
    if proto != 6:                                                              #filtering only tcp
        return None
    if internet_checksum(raw[:ihl_bytes]) != 0:                                 #verifying ip header checksum
        return None

    ident = struct.unpack("!H", raw[4:6])[0]
    ttl = raw[8]
    src = socket.inet_ntoa(raw[12:16])
    dst = socket.inet_ntoa(raw[16:20])
    payload = raw[ihl_bytes:tot_len]
    return IPInfo(src=src, dst=dst, ttl=ttl, ident=ident, payload=payload)


#........................................parse tcp options........................................
def parse_tcp_options(opts: bytes) -> Optional[int]:
    i = 0
    mss = None
    while i < len(opts):
        kind = opts[i]
        if kind == 0:                                                           #end of option list
            break
        elif kind == 1:                                                         #nop (single byte)
            i += 1
            continue
        else:
            if i + 1 >= len(opts):
                break
            opt_len = opts[i + 1]
            if opt_len < 2 or i + opt_len > len(opts):
                break
            if kind == 2 and opt_len == 4:                                      #mss option kind 2 length 4
                mss = struct.unpack("!H", opts[i + 2:i + 4])[0]
            i += opt_len
    return mss


#........................................parse tcp segment........................................
def parse_tcp_segment(ip: IPInfo) -> Optional[TCPSeg]:
    data = ip.payload
    if len(data) < 20:                                                          #minimum tcp header size
        return None
    data_offset = (data[12] >> 4) & 0x0f
    header_len = data_offset * 4
    if data_offset < 5 or len(data) < header_len:
        return None
    if tcp_checksum(ip.src, ip.dst, data) != 0:                                 #verifying tcp pseudo-header checksum
        return None

    sport, dport, seq, ack = struct.unpack("!HHII", data[0:12])
    flags = data[13]
    window = struct.unpack("!H", data[14:16])[0]
    opts = data[20:header_len]
    mss = parse_tcp_options(opts)
    payload = data[header_len:]
    return TCPSeg(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=window, mss=mss, payload=payload)


#.......................................generate new ip id........................................
def new_ip_id() -> int:
    global _ip_id_counter
    val = _ip_id_counter
    _ip_id_counter += 1
    if _ip_id_counter > 65535:
        _ip_id_counter = 1
    return val

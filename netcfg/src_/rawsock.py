"""
rawsock.py - the raw IP socket.                                        (section 6.2)

ROLE
    The only module that touches the network. Wraps one raw socket so the rest
    of the code can say send(packet, dst) and recv(timeout).

RULES FROM THE ASSIGNMENT
    * Raw IP socket with IP_HDRINCL set: YOU supply the IP header. Letting the
      kernel add one = zero marks for Part B.
    * No SOCK_STREAM, no connect()/listen()/accept() on TCP, no AF_PACKET.
    * Needs root.

THINGS TO KNOW
    * Create it as socket(AF_INET, SOCK_RAW, IPPROTO_TCP). A raw socket opened
      with IPPROTO_RAW can send but never receives, so it is no use here.
    * It receives a copy of EVERY TCP packet arriving at the machine (including
      traffic for other programs), each with its IP header attached. Filtering
      for "is this mine" is tcp.py's job (T5).
    * The kernel has no real socket for your connection, so it answers your
      peer's packets with RST. During development drop those with:
          sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    * For the server (accepts connections "for any of the machine's addresses
      and replies from the address the SYN was sent to"): the destination
      address of the incoming SYN is the source address of your SYN-ACK.
"""
from typing import Optional


class RawSocket:
    """One raw socket for both sending and receiving TCP/IPv4."""

    def __init__(self) -> None:
        """Create the socket and enable IP_HDRINCL (socket option at level
        IPPROTO_IP). Do not bind to a port - raw sockets have none."""
        raise NotImplementedError

    def send(self, ip_packet: bytes, dst_ip: str) -> None:
        """Send one COMPLETE IP packet (IP header + TCP segment) towards dst_ip.
        With a raw socket the address tuple is (dst_ip, 0)."""
        raise NotImplementedError

    def recv(self, timeout: float) -> Optional[bytes]:
        """Wait up to `timeout` seconds for a packet and return its raw bytes
        (IP header included), or None if nothing arrived. Use select() for the
        wait so your retransmission timers can drive the timeout. A timeout of 0
        must poll without blocking. Large buffer (65535) so nothing is cut."""
        raise NotImplementedError

    def close(self) -> None:
        """Close the socket."""
        raise NotImplementedError


def pick_local_ip(dst_ip: str) -> str:
    """Return the local address the OS would use to reach dst_ip, so the client
    knows what source address to put in its packets (it must match the IP
    header and the TCP pseudo-header). Trick: open a UDP socket, connect() it to
    (dst_ip, 9) - no packet is sent - read getsockname()[0], close it."""
    raise NotImplementedError

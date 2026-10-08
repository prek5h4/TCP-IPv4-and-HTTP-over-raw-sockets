"""
tcp.py - the TCP engine: handshake, reliable transfer, teardown.   (T5-T13)

ROLE
    One TCPConnection object = one connection (only one at a time is required).
    The HTTP client/server call connect()/accept(), send(), recv(), close() and
    never see packets. Everything else (packet building, logging, congestion
    control) is delegated to packet.py, pktlog.py, congestion.py.

ARCHITECTURE: ONE SINGLE-THREADED EVENT LOOP
    Every blocking call (connect, send, recv, close) is implemented by looping
    _pump(): wait for a packet OR the nearest timer deadline, handle whatever
    happened, repeat until the call's goal is reached. No threads, no locks.
    Timers are just deadlines (time.monotonic() values) that _next_deadline()
    collects and _pump() checks after each wake-up.

STATE YOU WILL NEED (suggested names)
    Endpoints : local_ip, local_port, remote_ip, remote_port
    State enum: see State below
    Sending   : iss (random initial seq, T6), snd_una (oldest unacked byte),
                snd_nxt (next new byte), send_buf (bytes the app queued),
                inflight (ordered list of SentSegment), peer_mss (default 536
                until the peer's SYN/SYN-ACK tells you), peer_window
    Receiving : irs (peer's initial seq), rcv_nxt (next byte expected),
                ooo (out-of-order buffer: dict seq -> bytes), rx_data (in-order
                bytes ready for the app), peer_fin_seen
    Timers    : rto + RTT estimator, retransmission deadline, "last progress"
                time (10 s give-up, T10), handshake and close deadlines

SEQUENCE NUMBERS
    32-bit and they WRAP. Never compare with < or >. Use seq_lt/seq_leq below
    ("a is before b" = (a - b) mod 2^32 has its top bit set). SYN and FIN each
    consume one sequence number; pure ACKs consume none.

STATE MACHINE (simplified; no TIME_WAIT needed)
    Client: CLOSED -> SYN_SENT -> ESTABLISHED -> (FIN_WAIT or CLOSE_WAIT) -> DONE
    Server: CLOSED -> LISTEN -> SYN_RCVD -> ESTABLISHED -> ... -> DONE
    RST at any time -> ABORTED (T8, immediately, raise TCPError).

TIMING RULES FROM THE ASSIGNMENT
    T7  handshake : retransmit SYN / SYN-ACK within 1 s; keep trying >= 6 s.
    T9  teardown  : ACK the peer's FIN. After sending your FIN, retransmit until
                    acked and wait for the peer's FIN; give up after <= 2 s.
    T10 sending   : RTO <= 1 s; give up if nothing is acked for 10 s.
    T11 receiving : advertise a FIXED window of 65535; ACK EVERY data segment
                    (also duplicate and out-of-order ones) with rcv_nxt.

DEBUGGING ADVICE
    Build in this order: handshake -> one request/response on a clean network ->
    teardown -> retransmission -> out-of-order buffering -> congestion control.
    Keep a capture (tcpdump -nn -w) of every failed run.
"""
import enum
from dataclasses import dataclass
from typing import Optional

from packet import IPInfo, TCPSeg
from rawsock import RawSocket
from pktlog import PacketLogger
from congestion import RenoCongestion

HANDSHAKE_RETX = 1.0      # T7: resend SYN / SYN-ACK at least this often
HANDSHAKE_TOTAL = 6.5     # T7: keep trying for at least 6 s (a little margin)
MAX_RTO = 1.0             # T10: RTO must never exceed this
NO_PROGRESS_LIMIT = 10.0  # T10: abort if nothing acked this long
CLOSE_TIMEOUT = 2.0       # T9
RECV_WINDOW = 65535       # T11
OUR_MSS = 1460


class State(enum.Enum):
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RCVD = 3
    ESTABLISHED = 4
    FIN_WAIT = 5       # we sent our FIN; waiting for its ACK and/or the peer's FIN
    CLOSE_WAIT = 6     # peer sent FIN first; we have not closed yet
    LAST_ACK = 7       # we replied to the peer's FIN with our own; waiting for ACK
    DONE = 8           # finished cleanly
    ABORTED = 9        # RST received or gave up


class TCPError(Exception):
    """Connect failure, reset, or timeout. The HTTP layers map this to a clean
    failure (client: exit code 2; server: drop the connection and carry on)."""


@dataclass
class SentSegment:
    """Bookkeeping for one transmitted-but-unacknowledged segment."""
    seq: int            # first sequence number it covers
    data: bytes         # payload (empty for a bare SYN/FIN)
    flags: int          # so a retransmission repeats SYN/FIN correctly
    sent_at: float      # time of (last) transmission, for RTT samples
    retransmitted: bool # Karn's rule: no RTT sample from retransmitted data


class TCPConnection:
    def __init__(self, sock: RawSocket, local_ip: str, local_port: int,
                 logger: PacketLogger) -> None:
        """Store the arguments, set state CLOSED, choose a random ISN (T6) and
        initialise every field listed in the module header (Reno object with
        OUR_MSS, empty buffers, rto = initial value <= MAX_RTO)."""
        raise NotImplementedError

    # ---------------- public API (used by the HTTP layers) ----------------

    def connect(self, remote_ip: str, remote_port: int) -> None:
        """ACTIVE OPEN (client). Send SYN (MSS option 1460 only), then wait for
        the SYN-ACK in the pump loop, retransmitting the SYN every <= 1 s.
        On SYN-ACK: record irs, rcv_nxt = irs + 1, peer_mss, peer_window; send
        the final ACK; state ESTABLISHED. Raise TCPError on RST (refused) or
        after HANDSHAKE_TOTAL seconds."""
        raise NotImplementedError

    def accept(self, timeout: Optional[float] = None) -> bool:
        """PASSIVE OPEN (server) on local_port. Wait for a SYN to our port at
        ANY local address; remember who sent it, and use the address the SYN
        was sent TO as our local_ip for everything that follows. Reply with a
        SYN-ACK (retransmitting per T7), wait for the final ACK, go
        ESTABLISHED. Return True on success, False if `timeout` expires first.
        A misbehaving client must never raise out of here or hang forever."""
        raise NotImplementedError

    def send(self, data: bytes) -> None:
        """Queue `data` and block until ALL of it is acknowledged. Keep calling
        _try_send() and _pump(). Raise TCPError on RST or after 10 s without
        progress (T10)."""
        raise NotImplementedError

    def recv(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        """Return up to max_bytes of in-order data, blocking until some is
        available. Return b'' once the peer's FIN has been received and all
        data delivered (= end of stream). Raise TCPError on RST. If `timeout`
        expires with nothing available raise TimeoutError (the server uses this
        for its 10 s request-head limit)."""
        raise NotImplementedError

    def close(self) -> None:
        """TEARDOWN (T9). Send FIN, retransmit it until acked, wait for the
        peer's FIN and ACK it. Give up after at most CLOSE_TIMEOUT seconds in
        total (never raise for this - just finish). Also covers the case where
        the peer already sent its FIN first. No TIME_WAIT."""
        raise NotImplementedError

    # ---------------- packet I/O ----------------

    def _send_segment(self, seq: int, ack: int, flags: int,
                      payload: bytes = b"", mss: Optional[int] = None) -> None:
        """THE ONLY place a packet leaves the machine. Build it (packet.build_packet
        with window = RECV_WINDOW and a fresh non-zero IP id), send it with the
        raw socket, then log it (logger.log_send). Retransmissions and pure ACKs
        must go through here too so they are logged (section 2.6)."""
        raise NotImplementedError

    def _recv_packet(self, timeout: float) -> Optional[TCPSeg]:
        """Read one raw packet and return a parsed TCPSeg, or None on timeout or
        if it is not acceptable. Steps: parse IP (checksum) -> parse TCP
        (checksum) -> _matches_connection() -> log_recv. Packets failing any
        step are dropped silently and NOT logged (T4, T5)."""
        raise NotImplementedError

    def _matches_connection(self, ip: IPInfo, seg: TCPSeg) -> bool:
        """T5. Active connection: src/dst addresses and both ports must match.
        While LISTENing: only dst port == local_port (and it is a SYN)."""
        raise NotImplementedError

    # ---------------- receive-side processing ----------------

    def _handle_segment(self, seg: TCPSeg) -> None:
        """Dispatch for an accepted segment: RST -> abort (T8); then update the
        peer's window; then ACK processing, data processing, FIN processing,
        and the handshake/teardown state changes."""
        raise NotImplementedError

    def _process_ack(self, seg: TCPSeg) -> None:
        """Handle the ACK field. New data acked (ack after snd_una, not beyond
        snd_nxt): free it from `inflight`, take an RTT sample (not from
        retransmitted segments), restart the RTO timer, note progress, tell
        congestion control (on_new_ack), then try to send more. Duplicate ACK
        (ack == snd_una, no payload, data in flight): on_dup_ack(); if it says
        True, retransmit the oldest segment immediately."""
        raise NotImplementedError

    def _process_data(self, seg: TCPSeg) -> None:
        """Handle payload (T11, T12). seg.seq == rcv_nxt: accept it, advance
        rcv_nxt, then pull any now-contiguous segments out of the out-of-order
        buffer. seq ahead of rcv_nxt but inside the window: store it in the
        buffer. Old or partly-old data: trim the part you already have so bytes
        are delivered exactly once. In EVERY case send a cumulative ACK
        (rcv_nxt) for this segment, including duplicates and out-of-order ones."""
        raise NotImplementedError

    def _process_fin(self, seg: TCPSeg) -> None:
        """A FIN is only 'real' once all data before it has arrived (its seq ==
        rcv_nxt after processing data). Then rcv_nxt += 1, ACK it, mark the
        stream finished and update the state."""
        raise NotImplementedError

    # ---------------- sending side and timers ----------------

    def _try_send(self) -> None:
        """While bytes_in_flight < min(cwnd, peer_window) and send_buf has data:
        cut a segment of at most min(1460, peer_mss) bytes, transmit it, record
        a SentSegment, advance snd_nxt, and arm the RTO timer if idle (T3, T10)."""
        raise NotImplementedError

    def _retransmit_oldest(self) -> None:
        """Resend the segment at snd_una (used for RTO and fast retransmit).
        Mark it retransmitted so it gives no RTT sample (Karn's rule)."""
        raise NotImplementedError

    def _on_rto(self) -> None:
        """Retransmission timer expired: tell congestion control
        (on_timeout), retransmit the oldest segment, back the RTO off (double it
        but never above MAX_RTO) and re-arm. If nothing has been acked for
        NO_PROGRESS_LIMIT seconds, abort with TCPError (T10)."""
        raise NotImplementedError

    def _update_rtt(self, sample: float) -> None:
        """RTT estimator (Jacobson/Karels): first sample sets srtt and rttvar;
        later samples smooth them; rto = srtt + 4*rttvar, clamped between a
        small minimum and MAX_RTO."""
        raise NotImplementedError

    def _next_deadline(self) -> Optional[float]:
        """Earliest of all armed timers (retransmission, handshake, close,
        no-progress); None if none is armed."""
        raise NotImplementedError

    def _pump(self, max_wait: float) -> None:
        """ONE step of the event loop: wait at most min(max_wait, time until
        _next_deadline()) for a packet; if one arrives, _handle_segment() it;
        then fire any timer that has expired (_on_rto, handshake retransmit,
        close timeout)."""
        raise NotImplementedError


def seq_lt(a: int, b: int) -> bool:
    """True if sequence number a comes before b in 32-bit modular space."""
    raise NotImplementedError


def seq_leq(a: int, b: int) -> bool:
    """True if a is before or equal to b in 32-bit modular space."""
    raise NotImplementedError


def seq_add(a: int, n: int) -> int:
    """(a + n) wrapped to 32 bits."""
    raise NotImplementedError

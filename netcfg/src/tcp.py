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
import random
import time
from dataclasses import dataclass
from typing import Optional

from packet import IPInfo, TCPSeg, build_packet, parse_ip_packet, parse_tcp_segment, new_ip_id, FIN, SYN, RST, PSH, ACK
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
        self.sock = sock
        self.local_ip = local_ip
        self.local_port = local_port
        self.logger = logger

        self.remote_ip = ""
        self.remote_port = 0
        self.state = State.CLOSED

        # Sending state
        self.iss = random.randint(0, 0xffffffff)
        self.snd_una = self.iss
        self.snd_nxt = self.iss
        self.send_buf = bytearray()
        self.inflight: list[SentSegment] = []
        self.peer_mss = 536
        self.peer_window = 65535

        # Receiving state
        self.irs = 0
        self.rcv_nxt = 0
        self.ooo: dict[int, bytes] = {}
        self.rx_data = bytearray()
        self.peer_fin_seen = False
        self.peer_fin_seq: Optional[int] = None
        self.our_fin_sent = False
        self.our_fin_seq: Optional[int] = None
        self.our_fin_acked = False

        self.congestion = RenoCongestion(OUR_MSS)

        # Timers / RTT estimator
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.rto = 0.5  # initial <= MAX_RTO
        self.rto_deadline: Optional[float] = None

        self.last_progress_time = time.monotonic()
        self.handshake_deadline: Optional[float] = None
        self.handshake_start_time: Optional[float] = None
        self.close_start_time: Optional[float] = None
        self.close_deadline: Optional[float] = None

    # ---------------- public API (used by the HTTP layers) ----------------

    def connect(self, remote_ip: str, remote_port: int) -> None:
        """ACTIVE OPEN (client). Send SYN (MSS option 1460 only), then wait for
        the SYN-ACK in the pump loop, retransmitting the SYN every <= 1 s.
        On SYN-ACK: record irs, rcv_nxt = irs + 1, peer_mss, peer_window; send
        the final ACK; state ESTABLISHED. Raise TCPError on RST (refused) or
        after HANDSHAKE_TOTAL seconds."""
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.state = State.SYN_SENT
        self.handshake_start_time = time.monotonic()

        self._send_segment(seq=self.iss, ack=0, flags=SYN, mss=OUR_MSS)
        self.snd_nxt = seq_add(self.iss, 1)
        self.handshake_deadline = time.monotonic() + HANDSHAKE_RETX

        while self.state == State.SYN_SENT:
            if time.monotonic() - self.handshake_start_time >= HANDSHAKE_TOTAL:
                self.state = State.ABORTED
                raise TCPError("Handshake timed out (SYN not answered)")
            self._pump(0.1)
            if self.state == State.ABORTED:
                raise TCPError("Connection reset or refused by peer")

        if self.state != State.ESTABLISHED:
            raise TCPError(f"Connection failed (state: {self.state})")

        self.last_progress_time = time.monotonic()
        self.handshake_deadline = None

    def accept(self, timeout: Optional[float] = None) -> bool:
        """PASSIVE OPEN (server) on local_port. Wait for a SYN to our port at
        ANY local address; remember who sent it, and use the address the SYN
        was sent TO as our local_ip for everything that follows. Reply with a
        SYN-ACK (retransmitting per T7), wait for the final ACK, go
        ESTABLISHED. Return True on success, False if `timeout` expires first.
        A misbehaving client must never raise out of here or hang forever."""
        self.state = State.LISTEN
        start_time = time.monotonic()

        try:
            while self.state == State.LISTEN:
                if timeout is not None and (time.monotonic() - start_time) >= timeout:
                    return False
                self._pump(0.1)
                if self.state == State.ABORTED:
                    return False

            if self.state == State.SYN_RCVD:
                while self.state == State.SYN_RCVD:
                    if time.monotonic() - self.handshake_start_time >= HANDSHAKE_TOTAL:
                        self.state = State.CLOSED
                        return False
                    self._pump(0.1)
                    if self.state == State.ABORTED:
                        return False

            if self.state == State.ESTABLISHED:
                self.last_progress_time = time.monotonic()
                self.handshake_deadline = None
                return True

            return False
        except TCPError:
            self.state = State.CLOSED
            return False

    def send(self, data: bytes) -> None:
        """Queue `data` and block until ALL of it is acknowledged. Keep calling
        _try_send() and _pump(). Raise TCPError on RST or after 10 s without
        progress (T10)."""
        if self.state in (State.CLOSED, State.ABORTED, State.DONE):
            raise TCPError("Cannot send on closed connection")

        self.send_buf.extend(data)
        self._try_send()

        while len(self.send_buf) > 0 or len(self.inflight) > 0:
            if self.state in (State.ABORTED, State.CLOSED):
                raise TCPError("Connection closed or aborted during send")

            self._pump(0.05)
            self._try_send()

            if time.monotonic() - self.last_progress_time >= NO_PROGRESS_LIMIT:
                self.state = State.ABORTED
                raise TCPError("No progress for 10s (timeout)")

    def recv(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        """Return up to max_bytes of in-order data, blocking until some is
        available. Return b'' once the peer's FIN has been received and all
        data delivered (= end of stream). Raise TCPError on RST. If `timeout`
        expires with nothing available raise TimeoutError (the server uses this
        for its 10 s request-head limit)."""
        start_time = time.monotonic()

        while len(self.rx_data) == 0:
            if self.peer_fin_seen:
                return b""
            if self.state in (State.ABORTED, State.CLOSED):
                raise TCPError("Connection closed or aborted during recv")

            if timeout is not None:
                remaining = timeout - (time.monotonic() - start_time)
                if remaining <= 0:
                    raise TimeoutError("recv timed out")
                self._pump(min(0.1, remaining))
            else:
                self._pump(0.1)

        chunk = bytes(self.rx_data[:max_bytes])
        del self.rx_data[:max_bytes]
        return chunk

    def close(self) -> None:
        """TEARDOWN (T9). Send FIN, retransmit it until acked, wait for the
        peer's FIN and ACK it. Give up after at most CLOSE_TIMEOUT seconds in
        total (never raise for this - just finish). Also covers the case where
        the peer already sent its FIN first. No TIME_WAIT."""
        if self.state in (State.CLOSED, State.DONE, State.ABORTED):
            return

        try:
            if not self.our_fin_sent:
                self.our_fin_sent = True
                self.our_fin_seq = self.snd_nxt
                self._send_segment(seq=self.our_fin_seq, ack=self.rcv_nxt, flags=(FIN | ACK))
                self.snd_nxt = seq_add(self.snd_nxt, 1)
                if self.state == State.CLOSE_WAIT:
                    self.state = State.LAST_ACK
                else:
                    self.state = State.FIN_WAIT

            self.close_start_time = time.monotonic()
            self.close_deadline = time.monotonic() + 0.5

            while self.state not in (State.DONE, State.ABORTED):
                if time.monotonic() - self.close_start_time >= CLOSE_TIMEOUT:
                    self.state = State.DONE
                    break

                if self.our_fin_acked and self.peer_fin_seen:
                    self.state = State.DONE
                    break

                if not self.our_fin_acked and time.monotonic() >= self.close_deadline:
                    self._send_segment(seq=self.our_fin_seq, ack=self.rcv_nxt, flags=(FIN | ACK))
                    self.close_deadline = time.monotonic() + 0.5

                self._pump(0.05)
        except Exception:
            self.state = State.DONE

    # ---------------- packet I/O ----------------

    def _send_segment(self, seq: int, ack: int, flags: int,
                      payload: bytes = b"", mss: Optional[int] = None) -> None:
        """THE ONLY place a packet leaves the machine. Build it (packet.build_packet
        with window = RECV_WINDOW and a fresh non-zero IP id), send it with the
        raw socket, then log it (logger.log_send). Retransmissions and pure ACKs
        must go through here too so they are logged (section 2.6)."""
        ident = new_ip_id()
        pkt = build_packet(src=self.local_ip, dst=self.remote_ip,
                           sport=self.local_port, dport=self.remote_port,
                           seq=seq, ack=ack, flags=flags, window=RECV_WINDOW,
                           ident=ident, payload=payload, mss=mss)
        self.sock.send(pkt, self.remote_ip)
        self.logger.log_send(src=self.local_ip, sport=self.local_port,
                             dst=self.remote_ip, dport=self.remote_port,
                             ttl=64, ident=ident, seq=seq, ack=ack,
                             flags=flags, win=RECV_WINDOW,
                             length=len(payload), mss=mss)

    def _recv_packet(self, timeout: float) -> Optional[TCPSeg]:
        """Read one raw packet and return a parsed TCPSeg, or None on timeout or
        if it is not acceptable. Steps: parse IP (checksum) -> parse TCP
        (checksum) -> _matches_connection() -> log_recv. Packets failing any
        step are dropped silently and NOT logged (T4, T5)."""
        raw = self.sock.recv(timeout)
        if raw is None:
            return None
        ip = parse_ip_packet(raw)
        if ip is None:
            return None
        seg = parse_tcp_segment(ip)
        if seg is None:
            return None
        if not self._matches_connection(ip, seg):
            return None
        self.logger.log_recv(src=ip.src, sport=seg.sport, dst=ip.dst, dport=seg.dport,
                             ttl=ip.ttl, ident=ip.ident, seq=seg.seq, ack=seg.ack,
                             flags=seg.flags, win=seg.window, length=len(seg.payload),
                             mss=seg.mss)
        if self.state == State.LISTEN:
            self.local_ip = ip.dst
            self.remote_ip = ip.src
            self.remote_port = seg.sport
        return seg

    def _matches_connection(self, ip: IPInfo, seg: TCPSeg) -> bool:
        """T5. Active connection: src/dst addresses and both ports must match.
        While LISTENing: only dst port == local_port (and it is a SYN)."""
        if self.state == State.LISTEN:
            return (seg.dport == self.local_port and
                    bool(seg.flags & SYN) and
                    not bool(seg.flags & ACK))
        if self.state == State.SYN_SENT:
            return (ip.src == self.remote_ip and
                    seg.sport == self.remote_port and
                    seg.dport == self.local_port)
        return (ip.src == self.remote_ip and
                ip.dst == self.local_ip and
                seg.sport == self.remote_port and
                seg.dport == self.local_port)

    # ---------------- receive-side processing ----------------

    def _handle_segment(self, seg: TCPSeg) -> None:
        """Dispatch for an accepted segment: RST -> abort (T8); then update the
        peer's window; then ACK processing, data processing, FIN processing,
        and the handshake/teardown state changes."""
        if seg.flags & RST:
            self.state = State.ABORTED
            raise TCPError("Connection reset by peer (RST)")

        if self.state == State.LISTEN:
            self.irs = seg.seq
            self.rcv_nxt = seq_add(self.irs, 1)
            if seg.mss is not None:
                self.peer_mss = seg.mss
            self.peer_window = seg.window
            self.state = State.SYN_RCVD
            self.handshake_start_time = time.monotonic()
            self._send_segment(seq=self.iss, ack=self.rcv_nxt,
                               flags=(SYN | ACK), mss=OUR_MSS)
            self.snd_nxt = seq_add(self.iss, 1)
            self.handshake_deadline = time.monotonic() + HANDSHAKE_RETX
            return

        if self.state == State.SYN_SENT:
            if (seg.flags & (SYN | ACK)) == (SYN | ACK):
                if seg.ack == self.snd_nxt:
                    self.irs = seg.seq
                    self.rcv_nxt = seq_add(self.irs, 1)
                    self.snd_una = seg.ack
                    if seg.mss is not None:
                        self.peer_mss = seg.mss
                    self.peer_window = seg.window
                    self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)
                    self.state = State.ESTABLISHED
                    self.handshake_deadline = None
            return

        self.peer_window = seg.window

        if self.state == State.SYN_RCVD:
            if seg.flags & ACK:
                if seg.ack == self.snd_nxt:
                    self.snd_una = seg.ack
                    self.state = State.ESTABLISHED
                    self.handshake_deadline = None

        if seg.flags & ACK:
            self._process_ack(seg)

        if len(seg.payload) > 0:
            self._process_data(seg)

        if seg.flags & FIN:
            self._process_fin(seg)

    def _process_ack(self, seg: TCPSeg) -> None:
        """Handle the ACK field. New data acked (ack after snd_una, not beyond
        snd_nxt): free it from `inflight`, take an RTT sample (not from
        retransmitted segments), restart the RTO timer, note progress, tell
        congestion control (on_new_ack), then try to send more. Duplicate ACK
        (ack == snd_una, no payload, data in flight): on_dup_ack(); if it says
        True, retransmit the oldest segment immediately."""
        ack = seg.ack

        # Check for FIN acknowledgement
        if self.our_fin_sent and self.our_fin_seq is not None:
            if seq_leq(seq_add(self.our_fin_seq, 1), ack):
                self.our_fin_acked = True
                if self.state == State.LAST_ACK:
                    self.state = State.DONE
                elif self.state == State.FIN_WAIT and self.peer_fin_seen:
                    self.state = State.DONE

        if seq_lt(self.snd_una, ack) and seq_leq(ack, self.snd_nxt):
            bytes_acked = (ack - self.snd_una) & 0xffffffff
            self.snd_una = ack
            self.last_progress_time = time.monotonic()

            for s in self.inflight:
                seg_len = max(1, len(s.data)) if (s.flags & (SYN | FIN)) else len(s.data)
                seg_end = seq_add(s.seq, seg_len)
                if seq_leq(seg_end, ack) and not s.retransmitted:
                    sample = time.monotonic() - s.sent_at
                    self._update_rtt(sample)

            self.inflight = [
                s for s in self.inflight
                if seq_lt(ack, seq_add(s.seq, max(1, len(s.data)) if (s.flags & (SYN | FIN)) else len(s.data)))
            ]

            if len(self.inflight) > 0:
                self.rto_deadline = time.monotonic() + self.rto
            else:
                self.rto_deadline = None

            self.congestion.on_new_ack(bytes_acked)
            self._try_send()

        elif ack == self.snd_una:
            if len(self.inflight) > 0 and len(seg.payload) == 0 and not (seg.flags & (SYN | FIN)):
                flight_size = sum(len(s.data) for s in self.inflight)
                if self.congestion.on_dup_ack(flight_size):
                    self._retransmit_oldest()
                    self.rto_deadline = time.monotonic() + self.rto

    def _process_data(self, seg: TCPSeg) -> None:
        """Handle payload (T11, T12). seg.seq == rcv_nxt: accept it, advance
        rcv_nxt, then pull any now-contiguous segments out of the out-of-order
        buffer. seq ahead of rcv_nxt but inside the window: store it in the
        buffer. Old or partly-old data: trim the part you already have so bytes
        are delivered exactly once. In EVERY case send a cumulative ACK
        (rcv_nxt) for this segment, including duplicates and out-of-order ones."""
        seg_len = len(seg.payload)
        if seg_len > 0:
            if seg.seq == self.rcv_nxt:
                self.rx_data.extend(seg.payload)
                self.rcv_nxt = seq_add(self.rcv_nxt, seg_len)
                self._drain_ooo()
            elif seq_lt(seg.seq, self.rcv_nxt):
                offset = (self.rcv_nxt - seg.seq) & 0xffffffff
                if offset < seg_len:
                    new_bytes = seg.payload[offset:]
                    self.rx_data.extend(new_bytes)
                    self.rcv_nxt = seq_add(self.rcv_nxt, len(new_bytes))
                    self._drain_ooo()
            elif seq_lt(self.rcv_nxt, seg.seq):
                if seq_lt(seg.seq, seq_add(self.rcv_nxt, RECV_WINDOW)):
                    self.ooo[seg.seq] = seg.payload

            # Check if out-of-order FIN now matches rcv_nxt
            if self.peer_fin_seq is not None and self.peer_fin_seq == self.rcv_nxt:
                self._activate_fin()

            # Always send a cumulative ACK for every data segment received
            self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)

    def _drain_ooo(self) -> None:
        """Drain contiguous blocks from the out-of-order buffer."""
        while True:
            found = False
            for ooo_seq in sorted(self.ooo.keys(), key=lambda s: (s - self.rcv_nxt) & 0xffffffff):
                if ooo_seq == self.rcv_nxt:
                    data = self.ooo.pop(ooo_seq)
                    self.rx_data.extend(data)
                    self.rcv_nxt = seq_add(self.rcv_nxt, len(data))
                    found = True
                    break
                elif seq_lt(ooo_seq, self.rcv_nxt):
                    data = self.ooo.pop(ooo_seq)
                    offset = (self.rcv_nxt - ooo_seq) & 0xffffffff
                    if offset < len(data):
                        new_bytes = data[offset:]
                        self.rx_data.extend(new_bytes)
                        self.rcv_nxt = seq_add(self.rcv_nxt, len(new_bytes))
                        found = True
                        break
            if not found:
                break

    def _activate_fin(self) -> None:
        """Process peer FIN when all preceding data has been delivered."""
        self.rcv_nxt = seq_add(self.rcv_nxt, 1)
        self.peer_fin_seen = True
        self.peer_fin_seq = None
        self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)
        if self.state == State.ESTABLISHED:
            self.state = State.CLOSE_WAIT
        elif self.state == State.FIN_WAIT:
            if self.our_fin_acked:
                self.state = State.DONE

    def _process_fin(self, seg: TCPSeg) -> None:
        """A FIN is only 'real' once all data before it has arrived (its seq ==
        rcv_nxt after processing data). Then rcv_nxt += 1, ACK it, mark the
        stream finished and update the state."""
        fin_seq = seq_add(seg.seq, len(seg.payload))
        if fin_seq == self.rcv_nxt:
            self._activate_fin()
        elif seq_lt(self.rcv_nxt, fin_seq):
            self.peer_fin_seq = fin_seq

    # ---------------- sending side and timers ----------------

    def _try_send(self) -> None:
        """While bytes_in_flight < min(cwnd, peer_window) and send_buf has data:
        cut a segment of at most min(1460, peer_mss) bytes, transmit it, record
        a SentSegment, advance snd_nxt, and arm the RTO timer if idle (T3, T10)."""
        mss = min(OUR_MSS, self.peer_mss)
        max_allowed = min(self.congestion.window(), self.peer_window)

        while len(self.send_buf) > 0:
            bytes_in_flight = sum(len(s.data) for s in self.inflight)
            allowed = min(mss, max_allowed - bytes_in_flight, len(self.send_buf))
            if allowed <= 0:
                break

            chunk = bytes(self.send_buf[:allowed])
            del self.send_buf[:allowed]

            sent_seg = SentSegment(seq=self.snd_nxt, data=chunk, flags=ACK,
                                   sent_at=time.monotonic(), retransmitted=False)
            self.inflight.append(sent_seg)
            self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK, payload=chunk)
            self.snd_nxt = seq_add(self.snd_nxt, len(chunk))

            if self.rto_deadline is None:
                self.rto_deadline = time.monotonic() + self.rto

    def _retransmit_oldest(self) -> None:
        """Resend the segment at snd_una (used for RTO and fast retransmit).
        Mark it retransmitted so it gives no RTT sample (Karn's rule)."""
        if len(self.inflight) > 0:
            oldest = self.inflight[0]
            oldest.retransmitted = True
            oldest.sent_at = time.monotonic()
            self._send_segment(seq=oldest.seq, ack=self.rcv_nxt,
                               flags=oldest.flags, payload=oldest.data)

    def _on_rto(self) -> None:
        """Retransmission timer expired: tell congestion control
        (on_timeout), retransmit the oldest segment, back the RTO off (double it
        but never above MAX_RTO) and re-arm. If nothing has been acked for
        NO_PROGRESS_LIMIT seconds, abort with TCPError (T10)."""
        if len(self.inflight) > 0:
            flight_size = sum(len(s.data) for s in self.inflight)
            self.congestion.on_timeout(flight_size)
            self._retransmit_oldest()
            self.rto = min(MAX_RTO, self.rto * 2.0)
            self.rto_deadline = time.monotonic() + self.rto

    def _update_rtt(self, sample: float) -> None:
        """RTT estimator (Jacobson/Karels): first sample sets srtt and rttvar;
        later samples smooth them; rto = srtt + 4*rttvar, clamped between a
        small minimum and MAX_RTO."""
        if self.srtt is None or self.rttvar is None:
            self.srtt = sample
            self.rttvar = sample / 2.0
        else:
            beta = 0.25
            alpha = 0.125
            self.rttvar = (1 - beta) * self.rttvar + beta * abs(self.srtt - sample)
            self.srtt = (1 - alpha) * self.srtt + alpha * sample

        rto = self.srtt + max(0.01, 4 * self.rttvar)
        self.rto = min(MAX_RTO, max(0.1, rto))

    def _next_deadline(self) -> Optional[float]:
        """Earliest of all armed timers (retransmission, handshake, close,
        no-progress); None if none is armed."""
        deadlines = []
        if self.rto_deadline is not None:
            deadlines.append(self.rto_deadline)
        if self.handshake_deadline is not None:
            deadlines.append(self.handshake_deadline)
        if self.close_deadline is not None and not self.our_fin_acked:
            deadlines.append(self.close_deadline)
        if len(deadlines) == 0:
            return None
        return min(deadlines)

    def _pump(self, max_wait: float) -> None:
        """ONE step of the event loop: wait at most min(max_wait, time until
        _next_deadline()) for a packet; if one arrives, _handle_segment() it;
        then fire any timer that has expired (_on_rto, handshake retransmit,
        close timeout)."""
        wait_time = max_wait
        d = self._next_deadline()
        if d is not None:
            rem = d - time.monotonic()
            wait_time = max(0.0, min(max_wait, rem))

        seg = self._recv_packet(wait_time)
        if seg is not None:
            self._handle_segment(seg)

        now = time.monotonic()

        # Handshake retransmissions
        if self.state == State.SYN_SENT and self.handshake_deadline is not None:
            if now >= self.handshake_deadline:
                self._send_segment(seq=self.iss, ack=0, flags=SYN, mss=OUR_MSS)
                self.handshake_deadline = now + HANDSHAKE_RETX

        elif self.state == State.SYN_RCVD and self.handshake_deadline is not None:
            if now >= self.handshake_deadline:
                self._send_segment(seq=self.iss, ack=self.rcv_nxt,
                                   flags=(SYN | ACK), mss=OUR_MSS)
                self.handshake_deadline = now + HANDSHAKE_RETX

        # Data RTO timer
        if self.rto_deadline is not None and now >= self.rto_deadline:
            self._on_rto()


def seq_lt(a: int, b: int) -> bool:
    """True if sequence number a comes before b in 32-bit modular space."""
    return ((a - b) & 0xffffffff) >= 0x80000000


def seq_leq(a: int, b: int) -> bool:
    """True if a is before or equal to b in 32-bit modular space."""
    return a == b or seq_lt(a, b)


def seq_add(a: int, n: int) -> int:
    """(a + n) wrapped to 32 bits."""
    return (a + n) & 0xffffffff

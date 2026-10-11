#................................................imports...........................................
import enum                                                                     #for connection states
import random                                                                   #for initial sequence numbers
import time                                                                     #for monotonic time tracking
from dataclasses import dataclass                                               #for data structures
from typing import Optional                                                     #for optional types

from packet import IPInfo, TCPSeg, build_packet, parse_ip_packet, parse_tcp_segment, new_ip_id, FIN, SYN, RST, PSH, ACK
from rawsock import RawSocket                                                   #for custom raw socket
from pktlog import PacketLogger                                                 #for packet logger
from congestion import RenoCongestion                                           #for congestion control

#...............................................constants.........................................
HANDSHAKE_RETX = 0.9                                                            #retransmit syn within 0.9s to stay under 1.0s limit
HANDSHAKE_TOTAL = 6.5                                                           #try handshake for at least 6.5 seconds
MAX_RTO = 0.9                                                                   #rto ceiling capped at 0.9s to strictly stay <= 1.0s
NO_PROGRESS_LIMIT = 10.0                                                        #give up if no ack received for 10 seconds
CLOSE_TIMEOUT = 1.8                                                             #teardown timeout set to 1.8s to strictly stay <= 2.0s
RECV_WINDOW = 65535                                                             #advertised receive window
OUR_MSS = 1460                                                                  #our default maximum segment size


#...........................................connection states.....................................
class State(enum.Enum):
    CLOSED = 0                                                                  #closed connection
    LISTEN = 1                                                                  #listening for incoming syn
    SYN_SENT = 2                                                                #active open syn sent
    SYN_RCVD = 3                                                                #syn received and syn-ack sent
    ESTABLISHED = 4                                                             #handshake complete
    FIN_WAIT = 5                                                                #we sent fin, waiting for peer
    CLOSE_WAIT = 6                                                              #peer sent fin first
    LAST_ACK = 7                                                                #we replied with fin, waiting for last ack
    DONE = 8                                                                    #connection closed cleanly
    ABORTED = 9                                                                 #aborted or reset


#...........................................exception class.......................................
class TCPError(Exception):
    pass


#.........................................sent segment tracker....................................
@dataclass
class SentSegment:
    seq: int                                                                    #starting sequence number
    data: bytes                                                                 #payload bytes
    flags: int                                                                  #tcp flags
    sent_at: float                                                              #timestamp when sent
    retransmitted: bool                                                         #karn's rule flag


#..........................................tcp connection engine..................................
class TCPConnection:
    def __init__(self, sock: RawSocket, local_ip: str, local_port: int,
                 logger: PacketLogger) -> None:
        self.sock = sock
        self.local_ip = local_ip
        self.local_port = local_port
        self.logger = logger

        self.remote_ip = ""
        self.remote_port = 0
        self.state = State.CLOSED

        self.iss = random.randint(0, 0xffffffff)                                #random initial sequence number
        self.snd_una = self.iss                                                 #oldest unacknowledged sequence
        self.snd_nxt = self.iss                                                 #next sequence number to send
        self.send_buf = bytearray()                                             #buffered unsent payload
        self.inflight: list[SentSegment] = []                                   #list of sent unacknowledged segments
        self.peer_mss = 536                                                     #peer mss defaults to 536
        self.peer_window = 65535                                                #peer advertised window

        self.irs = 0                                                            #peer initial sequence number
        self.rcv_nxt = 0                                                        #next byte expected
        self.ooo: dict[int, bytes] = {}                                         #out of order buffer
        self.rx_data = bytearray()                                              #in order received data
        self.peer_fin_seen = False                                              #peer fin accepted flag
        self.peer_fin_seq: Optional[int] = None                                 #sequence number of peer fin
        self.our_fin_sent = False                                               #our fin sent flag
        self.our_fin_seq: Optional[int] = None                                  #our fin sequence number
        self.our_fin_acked = False                                              #our fin acknowledged flag

        self.congestion = RenoCongestion(OUR_MSS)
        self.recovery_seq: Optional[int] = None                                 #recovery point for fast recovery

        self.srtt: Optional[float] = None                                       #smoothed rtt
        self.rttvar: Optional[float] = None                                     #rtt variation
        self.rto = 0.5                                                          #initial rto
        self.rto_deadline: Optional[float] = None                               #rto timer deadline

        self.last_progress_time = time.monotonic()                              #last time progress was made
        self.handshake_deadline: Optional[float] = None                         #handshake retransmit deadline
        self.handshake_start_time: Optional[float] = None                       #handshake starting time
        self.close_start_time: Optional[float] = None                           #teardown starting time
        self.close_deadline: Optional[float] = None                             #fin retransmission deadline

    #......................................active connect (client)................................
    def connect(self, remote_ip: str, remote_port: int) -> None:
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

    #.....................................passive accept (server).................................
    def accept(self) -> bool:
        self.state = State.LISTEN
        try:
            while self.state == State.LISTEN:
                self._pump(0.1)

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

    #........................................send method..........................................
    def send(self, data: bytes) -> None:
        if self.state in (State.CLOSED, State.ABORTED, State.DONE):
            raise TCPError("Cannot send on closed connection")

        self.last_progress_time = time.monotonic()                              #resetting progress timer when send starts
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

    #........................................recv method..........................................
    def recv(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
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

    #.......................................close teardown........................................
    def close(self) -> None:
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
            self.close_deadline = time.monotonic() + 0.4

            while self.state not in (State.DONE, State.ABORTED):
                if time.monotonic() - self.close_start_time >= CLOSE_TIMEOUT:
                    self.state = State.DONE
                    break

                if self.our_fin_acked and self.peer_fin_seen:
                    self.state = State.DONE
                    break

                if not self.our_fin_acked and time.monotonic() >= self.close_deadline:
                    self._send_segment(seq=self.our_fin_seq, ack=self.rcv_nxt, flags=(FIN | ACK))
                    self.close_deadline = time.monotonic() + 0.4

                self._pump(0.05)
        except Exception:
            self.state = State.DONE

    #...................................segment transmission......................................
    def _send_segment(self, seq: int, ack: int, flags: int,
                      payload: bytes = b"", mss: Optional[int] = None) -> None:
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

    #....................................packet reception.........................................
    def _recv_packet(self, timeout: float) -> Optional[TCPSeg]:
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

    #................................connection matching check....................................
    def _matches_connection(self, ip: IPInfo, seg: TCPSeg) -> bool:
        if self.state == State.LISTEN:
            return (seg.flags & SYN) and not (seg.flags & ACK) and seg.dport == self.local_port
        return (seg.dport == self.local_port and seg.sport == self.remote_port
                and ip.src == self.remote_ip and ip.dst == self.local_ip)

    #................................incoming segment handler.....................................
    def _handle_segment(self, seg: TCPSeg) -> None:
        if seg.flags & RST:
            self.state = State.ABORTED
            return

        if self.state == State.LISTEN:
            if not (seg.flags & SYN) or (seg.flags & ACK):
                return
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

    #......................................ack processing.........................................
    def _process_ack(self, seg: TCPSeg) -> None:
        ack = seg.ack

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

            #newreno partial ack vs full ack handling
            if self.congestion.in_fast_recovery:
                if self.recovery_seq is not None and seq_lt(ack, self.recovery_seq):
                    #partial ack: immediately retransmit the next unacknowledged segment
                    self._retransmit_oldest()
                    self.rto_deadline = time.monotonic() + self.rto
                else:
                    #full ack: recovery complete
                    self.congestion.on_new_ack(bytes_acked)
                    self.recovery_seq = None
            else:
                self.congestion.on_new_ack(bytes_acked)

            self._try_send()

        elif ack == self.snd_una:
            if len(self.inflight) > 0 and len(seg.payload) == 0 and not (seg.flags & (SYN | FIN)):
                flight_size = sum(len(s.data) for s in self.inflight)
                if self.congestion.on_dup_ack(flight_size):
                    self.recovery_seq = self.snd_nxt
                    self._retransmit_oldest()
                    self.rto_deadline = time.monotonic() + self.rto

    #.....................................data segment handler....................................
    def _process_data(self, seg: TCPSeg) -> None:
        #buffering payload, advancing rcv_nxt and sending cumulative ack
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

            #checking if out-of-order fin now matches rcv_nxt
            if self.peer_fin_seq is not None and self.peer_fin_seq == self.rcv_nxt:
                self._activate_fin()

            #always send cumulative ack for every data segment
            self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)

    #.................................out-of-order buffer drain...................................
    def _drain_ooo(self) -> None:
        #draining contiguous blocks from out-of-order dictionary
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

    #...................................fin activation helper....................................
    def _activate_fin(self) -> None:
        #advancing rcv_nxt for fin, updating state and acking
        self.rcv_nxt = seq_add(self.rcv_nxt, 1)
        self.peer_fin_seen = True
        self.peer_fin_seq = None
        self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)
        if self.state == State.ESTABLISHED:
            self.state = State.CLOSE_WAIT
        elif self.state == State.FIN_WAIT:
            if self.our_fin_acked:
                self.state = State.DONE

    #...................................peer fin segment handler..................................
    def _process_fin(self, seg: TCPSeg) -> None:
        #processing peer fin, handling out-of-order and retransmitted fins
        if self.peer_fin_seen:
            #retransmitted fin already processed: ack again with current rcv_nxt
            self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)
            return

        fin_seq = seq_add(seg.seq, len(seg.payload))
        if fin_seq == self.rcv_nxt:
            self._activate_fin()
        elif seq_lt(self.rcv_nxt, fin_seq):
            self.peer_fin_seq = fin_seq
            #out-of-order fin: still ack with current rcv_nxt
            self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)
        else:
            #stale fin: send ack with current rcv_nxt
            self._send_segment(seq=self.snd_nxt, ack=self.rcv_nxt, flags=ACK)

    #..................................segment transmission logic.................................
    def _try_send(self) -> None:
        #transmitting buffered data within min(cwnd, peer_window)
        mss = min(OUR_MSS, self.peer_mss)
        max_allowed = min(self.congestion.window(), self.peer_window)

        while len(self.send_buf) > 0:
            bytes_in_flight = sum(len(s.data) for s in self.inflight)
            window_leftover = max_allowed - bytes_in_flight
            if window_leftover <= 0:
                break

            #avoid sending tiny segment when leftover window is < mss and we have >= mss buffered
            if len(self.send_buf) >= mss and window_leftover < mss:
                break

            allowed = min(mss, window_leftover, len(self.send_buf))
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

    #....................................retransmission helper....................................
    def _retransmit_oldest(self) -> None:
        #resending oldest unacknowledged segment
        if len(self.inflight) > 0:
            oldest = self.inflight[0]
            oldest.retransmitted = True
            oldest.sent_at = time.monotonic()
            self._send_segment(seq=oldest.seq, ack=self.rcv_nxt,
                               flags=oldest.flags, payload=oldest.data)

    #.....................................rto timeout handler.....................................
    def _on_rto(self) -> None:
        #handling rto expiry: notify congestion control, back off and retransmit
        if len(self.inflight) > 0:
            flight_size = sum(len(s.data) for s in self.inflight)
            self.congestion.on_timeout(flight_size)
            self._retransmit_oldest()
            self.rto = min(MAX_RTO, self.rto * 2.0)
            self.rto_deadline = time.monotonic() + self.rto

    #...................................rtt estimation updates....................................
    def _update_rtt(self, sample: float) -> None:
        #jacobson/karels rtt estimator
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

    #...................................next deadline calculation.................................
    def _next_deadline(self) -> Optional[float]:
        #finding earliest timer deadline
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

    #......................................event pump loop........................................
    def _pump(self, max_wait: float) -> None:
        #single step of the single-threaded event loop
        wait_time = max_wait
        d = self._next_deadline()
        if d is not None:
            rem = d - time.monotonic()
            wait_time = max(0.0, min(max_wait, rem))

        seg = self._recv_packet(wait_time)
        if seg is not None:
            self._handle_segment(seg)

        now = time.monotonic()

        #handshake retransmissions
        if self.state == State.SYN_SENT and self.handshake_deadline is not None:
            if now >= self.handshake_deadline:
                self._send_segment(seq=self.iss, ack=0, flags=SYN, mss=OUR_MSS)
                self.handshake_deadline = now + HANDSHAKE_RETX

        elif self.state == State.SYN_RCVD and self.handshake_deadline is not None:
            if now >= self.handshake_deadline:
                self._send_segment(seq=self.iss, ack=self.rcv_nxt,
                                   flags=(SYN | ACK), mss=OUR_MSS)
                self.handshake_deadline = now + HANDSHAKE_RETX

        #data rto timer
        if self.rto_deadline is not None and now >= self.rto_deadline:
            self._on_rto()


#......................................sequence number arithmetic................................
def seq_lt(a: int, b: int) -> bool:
    #true if a comes before b in 32-bit modular arithmetic
    return ((a - b) & 0xffffffff) >= 0x80000000


def seq_leq(a: int, b: int) -> bool:
    #true if a is before or equal to b in 32-bit modular arithmetic
    return a == b or seq_lt(a, b)


def seq_add(a: int, n: int) -> int:
    #wrapping addition to 32 bits
    return (a + n) & 0xffffffff

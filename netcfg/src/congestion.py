"""
congestion.py - Reno-style congestion control.                         (T14)

ROLE
    Decides how many bytes the sender may have in flight (cwnd). It owns no
    sockets and no timers: tcp.py calls its on_* methods when events happen and
    asks window() before sending. That makes it easy to test alone, e.g. feed
    it a made-up sequence of ACKs / losses and plot cwnd.

PHASES (all quantities in BYTES)
    Slow start         cwnd < ssthresh : cwnd grows by up to 1 MSS per ACK
                       (so it roughly doubles every RTT).
    Congestion avoid.  cwnd >= ssthresh: cwnd grows ~1 MSS per RTT, i.e. add
                       MSS*MSS/cwnd for each new ACK.
    Fast retransmit    3 duplicate ACKs: lost segment is resent at once;
                       ssthresh = max(flight/2, 2*MSS); cwnd = ssthresh + 3*MSS.
    Fast recovery      each further dup ACK inflates cwnd by 1 MSS; the first
                       NEW ACK deflates cwnd to ssthresh and returns to
                       congestion avoidance. (Optional extra: NewReno handles
                       "partial ACKs" while in recovery.)
    Timeout (RTO)      ssthresh = max(flight/2, 2*MSS); cwnd = 1 MSS; slow start.

FAIRNESS GOAL
    Against curl sharing the bottleneck, your flow should end up with roughly an
    equal share. Easy ways to lose that: a huge initial window, increasing cwnd
    too fast, or not backing off on loss.

TESTING
    Log (time, cwnd, ssthresh) on every change and plot it - you want a sawtooth.
"""


class RenoCongestion:
    def __init__(self, mss: int) -> None:
        """Start with a small initial window (e.g. 2-10 MSS), a very large
        ssthresh, dup_acks = 0 and not in fast recovery."""
        self.mss = mss
        self.cwnd = float(3 * mss)
        self.ssthresh = 65535.0
        self.dup_acks = 0
        self.in_fast_recovery = False

    def window(self) -> int:
        """Current congestion window in bytes. The sender may have at most
        min(window(), peer's advertised window) unacknowledged bytes (T10)."""
        return max(self.mss, int(self.cwnd))

    def on_new_ack(self, bytes_acked: int) -> None:
        """The cumulative ACK advanced by bytes_acked. Reset the duplicate-ACK
        counter. If in fast recovery: deflate cwnd to ssthresh and leave
        recovery. Otherwise grow cwnd per the current phase (slow start vs
        congestion avoidance)."""
        self.dup_acks = 0
        if self.in_fast_recovery:
            self.cwnd = self.ssthresh
            self.in_fast_recovery = False
        else:
            if self.cwnd < self.ssthresh:
                self.cwnd += min(bytes_acked, self.mss)
            else:
                self.cwnd += (self.mss * self.mss) / self.cwnd

    def on_dup_ack(self, flight_size: int) -> bool:
        """A duplicate ACK arrived (same ack number, no new data acked, data
        outstanding). Count it. On the 3rd one enter fast retransmit/recovery
        (see header) and return True so the caller retransmits the first
        unacknowledged segment. During recovery inflate cwnd by 1 MSS per extra
        dup ACK. Otherwise return False. flight_size = bytes currently unacked."""
        self.dup_acks += 1
        if self.dup_acks == 3:
            self.ssthresh = max(float(flight_size // 2), float(2 * self.mss))
            self.cwnd = self.ssthresh + 3 * self.mss
            self.in_fast_recovery = True
            return True
        elif self.dup_acks > 3:
            if self.in_fast_recovery:
                self.cwnd += self.mss
            return False
        return False

    def on_timeout(self, flight_size: int) -> None:
        """The retransmission timer fired: apply the timeout rule in the header
        and leave fast recovery."""
        self.ssthresh = max(float(flight_size // 2), float(2 * self.mss))
        self.cwnd = float(self.mss)
        self.dup_acks = 0
        self.in_fast_recovery = False

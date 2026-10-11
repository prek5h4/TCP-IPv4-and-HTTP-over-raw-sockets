#........................................reno congestion control..................................
class RenoCongestion:

    def __init__(self, mss: int) -> None:
        self.mss = mss                                                          #maximum segment size
        self.cwnd = float(3 * mss)                                              #initial cwnd = 3 mss
        self.ssthresh = 65535.0                                                 #initial slow start threshold
        self.dup_acks = 0                                                       #duplicate ack counter
        self.in_fast_recovery = False                                           #fast recovery status flag

    def window(self) -> int:
        return max(self.mss, int(self.cwnd))                                    #returning current congestion window in bytes

    def on_new_ack(self, bytes_acked: int) -> None:
        self.dup_acks = 0                                                       #resetting duplicate ack count
        if self.in_fast_recovery:
            self.cwnd = self.ssthresh                                           #deflating window on recovery exit
            self.in_fast_recovery = False
        else:
            if self.cwnd < self.ssthresh:
                self.cwnd += min(bytes_acked, self.mss)                         #slow start phase: grow cwnd by bytes acked (up to 1 mss)
            else:
                self.cwnd += (self.mss * self.mss) / self.cwnd                  #congestion avoidance phase: additive increase ~ 1 mss per rtt

    def on_dup_ack(self, flight_size: int) -> bool:
        self.dup_acks += 1
        if self.dup_acks == 3:
            self.ssthresh = max(float(flight_size // 2), float(2 * self.mss))
            self.cwnd = self.ssthresh + 3 * self.mss
            self.in_fast_recovery = True
            return True                                                         #signals caller to retransmit oldest segment
        elif self.dup_acks > 3:
            if self.in_fast_recovery:
                self.cwnd += self.mss                                           #inflating cwnd for additional dup acks
            return False
        return False

    def on_timeout(self, flight_size: int) -> None:
        self.ssthresh = max(float(flight_size // 2), float(2 * self.mss))       #handling rto timeout: halving ssthresh and resetting cwnd to 1 mss
        self.cwnd = float(self.mss)                                             #resetting to 1 mss
        self.dup_acks = 0
        self.in_fast_recovery = False

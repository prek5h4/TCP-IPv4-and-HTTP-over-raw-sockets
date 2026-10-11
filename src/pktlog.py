#................................................imports...........................................
from typing import Optional                                                     #for optional type annotations


#.........................................packet logger class.....................................
class PacketLogger:
    
    def __init__(self, path: Optional[str]) -> None:
        
        self.path = path                                                        #setting path to log file
        self.file = None
        if path is not None:
            self.file = open(path, "w")                                         #truncating and opening log file

    def log_send(self, src: str, sport: int, dst: str, dport: int, ttl: int,
                 ident: int, seq: int, ack: int, flags: int, win: int,
                 length: int, mss: Optional[int]) -> None:
        if self.file is not None:                                               #logging transmitted segment
            line = self._format("SEND", src, sport, dst, dport, ttl, ident, seq, ack, flags, win, length, mss)
            self._write(line)

    def log_recv(self, src: str, sport: int, dst: str, dport: int, ttl: int,
                 ident: int, seq: int, ack: int, flags: int, win: int,
                 length: int, mss: Optional[int]) -> None:
        if self.file is not None:                                               #logging received segment
            line = self._format("RECV", src, sport, dst, dport, ttl, ident, seq, ack, flags, win, length, mss)
            self._write(line)

    def _format(self, direction: str, src: str, sport: int, dst: str,
                dport: int, ttl: int, ident: int, seq: int, ack: int,
                flags: int, win: int, length: int, mss: Optional[int]) -> str:
        seq_u = seq & 0xffffffff                                                #unsigned 32-bit sequence number
        ack_u = ack & 0xffffffff                                                #unsigned 32-bit acknowledgment number
        win_u = win & 0xffff                                                    #unsigned 16-bit window
        mss_str = str(mss) if mss is not None else "-"                          #mss value or dash
        flags_str = f"0x{flags:02x}"                                            #two-digit hex flags
        return f"{direction} {src}:{sport} > {dst}:{dport} ttl={ttl} id={ident} seq={seq_u} ack={ack_u} flags={flags_str} win={win_u} len={length} mss={mss_str}"

    def _write(self, line: str) -> None:
        if self.file is not None:                                               #writing line to file and flushing immediately
            self.file.write(line + "\n")
            self.file.flush()                                                   #ensuring line is persisted immediately

    def close(self) -> None:
        if self.file is not None:                                               #safely flushing and closing log file
            try:
                self.file.flush()
                self.file.close()
            except Exception:
                pass
            self.file = None

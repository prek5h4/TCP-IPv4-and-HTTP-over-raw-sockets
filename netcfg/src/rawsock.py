#................................................imports...........................................
import select                                                                   #for non-blocking polling and timeout multiplexing
import socket                                                                   #for raw and udp socket operations
from typing import Optional                                                     #for type annotations


#..........................................raw socket class.......................................
class RawSocket:

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)           #telling kernel we include ip header

    def send(self, ip_packet: bytes, dst_ip: str) -> None:
        self.sock.sendto(ip_packet, (dst_ip, 0))                                #sending complete ip packet towards destination address 

    def recv(self, timeout: float) -> Optional[bytes]:
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout))         #polling for incoming raw packet until timeout expires
        if r:
            data, _ = self.sock.recvfrom(65535)                                 #reading packet with max buffer size
            return data
        return None

    def close(self) -> None:
        try:                                                                    #closing socket resource safely
            self.sock.close()
        except Exception:
            pass


#......................................function to pick local ip..................................
def pick_local_ip(dst_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)                        #creating udp socket to query kernel routing
    try:
        s.connect((dst_ip, 9))                                                  #dummy connect without sending data
        local_ip = s.getsockname()[0]                                           #retrieving source interface address
    finally:
        s.close()
    return local_ip

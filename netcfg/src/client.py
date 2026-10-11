#................................................imports...........................................
import argparse                                                                 #for arguments parsing
import random                                                                   #for random port number
import socket                                                                   #for socket programming
import sys                                                                      #for system-level operations
from typing import Tuple                                                        #for type hinting

from rawsock import RawSocket, pick_local_ip                                    #for rawsocket and pick_local_ip functions
from pktlog import PacketLogger                                                 #for packet logger
from tcp import TCPConnection, TCPError                                         #for tcp connection and tcp error


#.........................................function for url parsing...........................................................
def parse_url(url_str: str) -> Tuple[str, int, str, str]:

    if not url_str.startswith("http://"):                                      #checking the url starts with http://
        raise ValueError("URL must start with http://")                        

    rest = url_str[len("http://"):]                                            #removing the http:// from the url
    slash_idx = rest.find("/")                                                 #finding the index of / in the url
    if slash_idx != -1:
        netloc = rest[:slash_idx]
        path = rest[slash_idx:]
    else:
        netloc = rest
        path = "/"

    if not netloc:                                                             #checking for invalid host
        raise ValueError("Invalid host in URL")

    host_header = netloc                                                       #host header as written in URL

    if ":" in netloc:                                                          #splitting the host and port if port is present
        parts = netloc.split(":", 1)
        host = parts[0]
        port = int(parts[1])
    else:
        host = netloc                                                          #setting default port to 80
        port = 80

    return host, port, path, host_header                                       #returning the host, port, path and host header


#...........................................function for reading http response.................................................
def read_http_response(conn: TCPConnection) -> Tuple[str, int, dict, bytes]:
    #reading and parsing the http response from the connection
    raw_response = bytearray()                                                  #buffer for raw response
    head_delimiter = b"\r\n\r\n"                                                #headers end delimiter

    while head_delimiter not in raw_response:                                   #waiting for the head delimiter
        chunk = conn.recv(4096, timeout=20.0)                                   #receiving response in chunks with timeout
        if not chunk:                                                           #if no chunk received, connection is closed
            raise ValueError("Connection closed before response headers complete")
        raw_response.extend(chunk)

    idx = raw_response.find(head_delimiter)                                     #finding the index of head delimiter
    head_bytes = raw_response[:idx]                                             #getting the head bytes
    body_already = raw_response[idx + 4:]                                       #getting the body bytes

    head_text = head_bytes.decode("iso-8859-1")                                 #decoding the head bytes
    lines = head_text.split("\r\n")                                             #splitting head bytes into lines
    
    if not lines or not lines[0]:                                               #checking for empty response header
        raise ValueError("Empty response header")

    status_line = lines[0]
    parts = status_line.split(" ", 2)                                           #splitting the status line
    if len(parts) < 2:                                                          #checking for malformed status line
        raise ValueError("Malformed status line")
    status_code = int(parts[1])                                                 #getting the status code

    headers = {}                                                                #initializing headers dictionary
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()                              #storing header name in lowercase

    body = bytearray()                                                          #initializing body as empty byte array
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    content_length_str = headers.get("content-length")

    if "chunked" in transfer_encoding:
        #................................chunked transfer encoding...................................
        buf = bytearray(body_already)                                           #buffer for chunked stream
        seen_zero_chunk = False                                                 #tracking if final zero chunk is received
        while True:
            #finding chunk header
            while b"\r\n" not in buf:
                chunk = conn.recv(4096, timeout=20.0)                           #reading chunk header with timeout
                if not chunk:
                    break
                buf.extend(chunk)

            c_idx = buf.find(b"\r\n")
            if c_idx == -1:
                break
            chunk_head = buf[:c_idx].decode("iso-8859-1")                       #chunk size line
            chunk_size_str = chunk_head.split(";")[0].strip()                   #ignoring chunk extensions
            try:
                chunk_size = int(chunk_size_str, 16)                           #parsing hex chunk length
            except ValueError:
                raise ValueError(f"Invalid chunk size: {chunk_size_str}")

            del buf[:c_idx + 2]                                                #removing header line and crlf

            if chunk_size == 0:
                seen_zero_chunk = True                                         #marked final chunk received
                break

            while len(buf) < chunk_size + 2:
                chunk = conn.recv(4096, timeout=20.0)                           #reading chunk data with timeout
                if not chunk:
                    break
                buf.extend(chunk)

            if len(buf) < chunk_size:
                raise ValueError("Incomplete chunk data")                      #chunk ended prematurely

            body.extend(buf[:chunk_size])                                      #saving chunk payload
            del buf[:chunk_size + 2]                                           #removing chunk and trailing crlf

        if not seen_zero_chunk:
            raise ValueError("Truncated chunked body: missing final 0 chunk")  #raising error if 0 chunk missing

    elif content_length_str is not None:
        #................................content-length handling.....................................
        content_length = int(content_length_str)                                #parsing total body length
        body.extend(body_already)
        while len(body) < content_length:
            chunk = conn.recv(4096, timeout=20.0)                               #receiving body chunks with timeout
            if not chunk:
                break
            body.extend(chunk)

        if len(body) < content_length:
            raise ValueError(f"Incomplete body: got {len(body)} of {content_length} bytes")
        body = body[:content_length]                                            #trimming extra bytes if any

    else:
        #..................................read until eof body.......................................
        body.extend(body_already)
        while True:
            chunk = conn.recv(4096, timeout=20.0)                               #reading till peer closes connection
            if not chunk:
                break
            body.extend(chunk)

    return status_line, status_code, headers, bytes(body)                       #returning status line, code, headers, body


#...............................................main function...................................................
def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP Client over raw TCP sockets")
    parser.add_argument("url", help="URL to download (http://...)")             #url positional argument
    parser.add_argument("-o", "--output", dest="outfile", default=None, help="Output file")
    parser.add_argument("--log", dest="logfile", default=None, help="Packet log file")

    try:
        args = parser.parse_args()                                              #parsing cli arguments
    except SystemExit:
        return 2

    try:
        host, port, path, host_hdr = parse_url(args.url)                        #parsing the given url
    except Exception as e:
        sys.stderr.write(f"Invalid URL: {e}\n")
        return 2

    try:
        remote_ip = socket.gethostbyname(host)                                  #resolving server hostname to ip
    except Exception as e:
        sys.stderr.write(f"DNS resolution failed: {e}\n")
        return 2

    sport = random.randint(61000, 65535)                                        #picking random ephemeral source port

    try:
        local_ip = pick_local_ip(remote_ip)                                     #finding appropriate local ip
    except Exception as e:
        sys.stderr.write(f"Failed to determine local IP: {e}\n")
        return 2

    sock = None
    logger = None
    try:
        sock = RawSocket()                                                      #opening raw socket
        logger = PacketLogger(args.logfile)                                     #initializing packet logger
        conn = TCPConnection(sock, local_ip, sport, logger)                    #creating tcp connection instance

        conn.connect(remote_ip, port)                                           #performing 3-way handshake

        #preparing http/1.1 get request
        request = f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode("iso-8859-1")
        conn.send(request)                                                      #sending http request over custom tcp

        status_line, status_code, headers, body = read_http_response(conn)      #reading http response

        #printing status line to standard error
        sys.stderr.write(status_line + "\n")
        sys.stderr.flush()

        #writing downloaded body
        if args.outfile is not None:
            with open(args.outfile, "wb") as f:                                 #saving to output file
                f.write(body)
        else:
            sys.stdout.buffer.write(body)                                       #printing to stdout
            sys.stdout.buffer.flush()

        conn.close()                                                            #tearing down tcp connection

        if 200 <= status_code <= 299:
            return 0                                                            #exit code 0 for 2xx success
        else:
            return 1                                                            #exit code 1 for 4xx/5xx responses

    except TCPError as e:
        sys.stderr.write(f"TCP Error: {e}\n")
        return 2                                                                #exit code 2 for network/tcp error
    except TimeoutError as e:
        sys.stderr.write(f"Timeout: {e}\n")
        return 2                                                                #exit code 2 for timeouts
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2                                                                #exit code 2 on any parsing/io error
    finally:
        if logger is not None:
            logger.close()                                                      #closing log file if opened
        if sock is not None:
            sock.close()                                                        #closing raw socket


#.............................................entry point.......................................................
if __name__ == "__main__":
    sys.exit(main())

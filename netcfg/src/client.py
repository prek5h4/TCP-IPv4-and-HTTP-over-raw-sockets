#!/usr/bin/env python3
"""
client.py - HTTP client implemented over raw TCP sockets. (Part C)
"""
import argparse
import random
import socket
import sys
from typing import Tuple

from rawsock import RawSocket, pick_local_ip
from pktlog import PacketLogger
from tcp import TCPConnection, TCPError


def parse_url(url_str: str) -> Tuple[str, int, str, str]:
    """Parse URL into (host, port, path, host_header) without external libraries."""
    if not url_str.startswith("http://"):
        raise ValueError("URL must start with http://")

    rest = url_str[len("http://"):]
    slash_idx = rest.find("/")
    if slash_idx != -1:
        netloc = rest[:slash_idx]
        path = rest[slash_idx:]
    else:
        netloc = rest
        path = "/"

    if not netloc:
        raise ValueError("Invalid host in URL")

    # Host header as written in URL
    host_header = netloc

    # Extract hostname and port
    if ":" in netloc:
        parts = netloc.split(":", 1)
        host = parts[0]
        port = int(parts[1])
    else:
        host = netloc
        port = 80

    return host, port, path, host_header


def read_http_response(conn: TCPConnection) -> Tuple[str, int, dict, bytes]:
    """Read and parse HTTP response from connection. Returns (status_line, status_code, headers, body)."""
    raw_response = bytearray()
    head_delimiter = b"\r\n\r\n"

    while head_delimiter not in raw_response:
        chunk = conn.recv(4096)
        if not chunk:
            raise ValueError("Connection closed before response headers complete")
        raw_response.extend(chunk)

    idx = raw_response.find(head_delimiter)
    head_bytes = raw_response[:idx]
    body_already = raw_response[idx + 4:]

    head_text = head_bytes.decode("iso-8859-1")
    lines = head_text.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("Empty response header")

    status_line = lines[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise ValueError("Malformed status line")
    status_code = int(parts[1])

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    body = bytearray()
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    content_length_str = headers.get("content-length")

    if "chunked" in transfer_encoding:
        # Chunked Transfer Encoding
        buf = bytearray(body_already)
        while True:
            # Find chunk header
            while b"\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)

            c_idx = buf.find(b"\r\n")
            if c_idx == -1:
                break
            chunk_head = buf[:c_idx].decode("iso-8859-1")
            chunk_size_str = chunk_head.split(";")[0].strip()
            chunk_size = int(chunk_size_str, 16)

            del buf[:c_idx + 2]  # remove header and CRLF

            if chunk_size == 0:
                # Last chunk reached
                break

            while len(buf) < chunk_size + 2:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)

            if len(buf) < chunk_size:
                raise ValueError("Incomplete chunk data")

            body.extend(buf[:chunk_size])
            del buf[:chunk_size + 2]  # remove chunk and trailing CRLF

    elif content_length_str is not None:
        content_length = int(content_length_str)
        body.extend(body_already)
        while len(body) < content_length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body.extend(chunk)

        if len(body) < content_length:
            raise ValueError(f"Incomplete body: got {len(body)} of {content_length} bytes")
        body = body[:content_length]

    else:
        # Read until EOF
        body.extend(body_already)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body.extend(chunk)

    return status_line, status_code, headers, bytes(body)


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP Client over raw TCP sockets")
    parser.add_argument("url", help="URL to download (http://...)")
    parser.add_argument("-o", "--output", dest="outfile", default=None, help="Output file")
    parser.add_argument("--log", dest="logfile", default=None, help="Packet log file")

    try:
        args = parser.parse_args()
    except SystemExit:
        return 2

    try:
        host, port, path, host_hdr = parse_url(args.url)
    except Exception as e:
        sys.stderr.write(f"Invalid URL: {e}\n")
        return 2

    try:
        remote_ip = socket.gethostbyname(host)
    except Exception as e:
        sys.stderr.write(f"DNS resolution failed: {e}\n")
        return 2

    sport = random.randint(61000, 65535)

    try:
        local_ip = pick_local_ip(remote_ip)
    except Exception as e:
        sys.stderr.write(f"Failed to determine local IP: {e}\n")
        return 2

    sock = None
    logger = None
    try:
        sock = RawSocket()
        logger = PacketLogger(args.logfile)
        conn = TCPConnection(sock, local_ip, sport, logger)

        conn.connect(remote_ip, port)

        request = f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode("iso-8859-1")
        conn.send(request)

        status_line, status_code, headers, body = read_http_response(conn)

        # Print status line to stderr
        sys.stderr.write(status_line + "\n")
        sys.stderr.flush()

        # Write body
        if args.outfile is not None:
            with open(args.outfile, "wb") as f:
                f.write(body)
        else:
            sys.stdout.buffer.write(body)
            sys.stdout.buffer.flush()

        conn.close()

        if 200 <= status_code <= 299:
            return 0
        else:
            return 1

    except TCPError as e:
        sys.stderr.write(f"TCP Error: {e}\n")
        return 2
    except TimeoutError as e:
        sys.stderr.write(f"Timeout: {e}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2
    finally:
        if logger is not None:
            logger.close()
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    sys.exit(main())

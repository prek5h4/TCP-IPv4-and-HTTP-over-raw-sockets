#!/usr/bin/env python3
"""
server.py - HTTP server implemented over raw TCP sockets. (Part D)
"""
import argparse
import os
import sys
from typing import Tuple

from rawsock import RawSocket
from pktlog import PacketLogger
from tcp import TCPConnection, TCPError

MIME_TYPES = {
    ".html": "text/html",
    ".htm": "text/html",
    ".txt": "text/plain",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".pdf": "application/pdf",
}


def get_content_type(file_path: str) -> str:
    _, ext = os.path.splitext(file_path)
    return MIME_TYPES.get(ext.lower(), "application/octet-stream")


def error_body(status_code: int, reason: str) -> bytes:
    html = f"<!DOCTYPE html>\n<html>\n<head><title>{status_code} {reason}</title></head>\n<body>\n<h1>{status_code} {reason}</h1>\n</body>\n</html>\n"
    return html.encode("utf-8")


def handle_request(head_data: bytes, docroot: str) -> Tuple[int, str, dict, bytes]:
    """Process request head and return (status_code, reason, headers, body)."""
    text = head_data.decode("iso-8859-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    request_line = lines[0]
    parts = request_line.split(" ")

    # Condition 1: The request line is not METHOD SP TARGET SP HTTP/x.y, or TARGET does not start with /
    if len(parts) != 3:
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    method, target, version = parts
    if not (version.startswith("HTTP/") and len(version.split("/")) == 2):
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    if not target.startswith("/"):
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    # Condition 2: METHOD is neither GET nor HEAD
    if method not in ("GET", "HEAD"):
        return 501, "Not Implemented", {"Content-Type": "text/html"}, error_body(501, "Not Implemented")

    # Condition 3: A path segment of TARGET is ..
    # First split target path (strip query string)
    path_only = target.split("?")[0]
    segments = path_only.split("/")
    if ".." in segments:
        return 403, "Forbidden", {"Content-Type": "text/html"}, error_body(403, "Forbidden")

    # Mapping: remove leading slash, append to docroot
    rel_path = path_only.lstrip("/")
    full_path = os.path.join(docroot, rel_path)

    if os.path.isdir(full_path) or path_only.endswith("/"):
        full_path = os.path.join(full_path, "index.html")

    # Condition 4: The file does not exist (or cannot be read as a regular file)
    if not os.path.isfile(full_path):
        return 404, "Not Found", {"Content-Type": "text/html"}, error_body(404, "Not Found")

    # Condition 5: Otherwise 200 OK
    try:
        with open(full_path, "rb") as f:
            content = f.read()
        ctype = get_content_type(full_path)
        if method == "HEAD":
            # HEAD has same headers as GET would, but no body
            return 200, "OK", {"Content-Type": ctype, "Content-Length": str(len(content))}, b""
        else:
            return 200, "OK", {"Content-Type": ctype}, content
    except Exception:
        return 404, "Not Found", {"Content-Type": "text/html"}, error_body(404, "Not Found")


def process_connection(conn: TCPConnection, docroot: str) -> None:
    """Read request head within 10s, send response, and close."""
    head_buf = bytearray()
    head_delimiter = b"\r\n\r\n"
    start_time = os.times().elapsed if hasattr(os, "times") else 0

    try:
        while head_delimiter not in head_buf:
            chunk = conn.recv(4096, timeout=10.0)
            if not chunk:
                break
            head_buf.extend(chunk)

        if head_delimiter not in head_buf:
            # 10s timeout or closed before complete head
            conn.close()
            return

        idx = head_buf.find(head_delimiter)
        request_head = bytes(head_buf[:idx])

        status_code, reason, headers, body = handle_request(request_head, docroot)

        if "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))
        headers["Connection"] = "close"

        header_lines = [f"HTTP/1.1 {status_code} {reason}"]
        for k, v in headers.items():
            header_lines.append(f"{k}: {v}")
        header_str = "\r\n".join(header_lines) + "\r\n\r\n"

        response_bytes = header_str.encode("iso-8859-1") + body
        conn.send(response_bytes)

    except (TimeoutError, TCPError):
        pass
    except Exception as e:
        sys.stderr.write(f"Server connection error: {e}\n")
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP Server over raw TCP sockets")
    parser.add_argument("-p", "--port", dest="port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("-d", "--docroot", dest="docroot", default="./www", help="Document root (default: ./www)")
    parser.add_argument("--log", dest="logfile", default=None, help="Packet log file")

    args = parser.parse_args()

    sock = None
    logger = None
    try:
        sock = RawSocket()
        logger = PacketLogger(args.logfile)

        while True:
            try:
                conn = TCPConnection(sock, "", args.port, logger)
                accepted = conn.accept()
                if accepted:
                    process_connection(conn, args.docroot)
            except Exception as e:
                # Server never exits because of a misbehaving client
                continue

    except KeyboardInterrupt:
        return 0
    finally:
        if logger is not None:
            logger.close()
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    sys.exit(main())

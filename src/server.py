#................................................imports...........................................
import argparse                                                                                        #for parsing command-line flags
import os                                                                                              #for filesystem and path checking
import sys                                                                                             #for standard error and exit codes
import time                                                                                            #for monotonic timers
from typing import Tuple                                                                               #for typing returns

from rawsock import RawSocket                                                                          #for custom raw socket
from pktlog import PacketLogger                                                                        #for packet logger
from tcp import TCPConnection, TCPError                                                                #for tcp engine and errors

#..............................................mime types.........................................
MIME_TYPES = {
    ".html": "text/html",                                                                              #html web pages
    ".htm": "text/html",                                                                               #htm extension
    ".txt": "text/plain",                                                                              #plain text files
    ".css": "text/css",                                                                                #stylesheets
    ".js": "application/javascript",                                                                   #javascript scripts
    ".json": "application/json",                                                                       #json data
    ".png": "image/png",                                                                               #png images
    ".jpg": "image/jpeg",                                                                              #jpeg images
    ".jpeg": "image/jpeg",                                                                             #jpeg images
    ".gif": "image/gif",                                                                               #gif images
    ".pdf": "application/pdf",                                                                         #pdf documents
}


#......................................function to get content type................................
def get_content_type(file_path: str) -> str:
    _, ext = os.path.splitext(file_path)                                                                 #looking up content type from file extension
    return MIME_TYPES.get(ext.lower(), "application/octet-stream")


#......................................function for html error body................................
def error_body(status_code: int, reason: str) -> bytes:
    html = f"<!DOCTYPE html>\n<html>\n<head><title>{status_code} {reason}</title></head>\n<body>\n<h1>{status_code} {reason}</h1>\n</body>\n</html>\n"
    return html.encode("utf-8")                                                                          #building simple standard html error message page


#.....................................function to handle request head..............................
def handle_request(head_data: bytes, docroot: str) -> Tuple[int, str, dict, bytes]:
    text = head_data.decode("iso-8859-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:                                                                        #empty request check
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    request_line = lines[0]
    parts = request_line.split(" ")

    #.......................cnd 1: request line must be METHOD SP TARGET SP HTTP/x.y.............................
    if len(parts) != 3:
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    method, target, version = parts
    if not method:                                                                                       #empty method gives 400
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    if not version.startswith("HTTP/"):                                                                  #version prefix check
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")
    ver_nums = version[5:].split(".")
    if len(ver_nums) != 2 or not ver_nums[0].isdigit() or not ver_nums[1].isdigit():                     #must be digits.digits
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    if not target.startswith("/"):                                                                       #target must start with slash
        return 400, "Bad Request", {"Content-Type": "text/html"}, error_body(400, "Bad Request")

    #.........................................cnd 2: method must be GET or HEAD....................................
    if method not in ("GET", "HEAD"):
        return 501, "Not Implemented", {"Content-Type": "text/html"}, error_body(501, "Not Implemented")

    #.........................................cnd 3: path traversal check..........................................
    path_only = target.split("?")[0]                                                                      #stripping query params
    segments = path_only.split("/")
    if ".." in segments:
        return 403, "Forbidden", {"Content-Type": "text/html"}, error_body(403, "Forbidden")

    rel_path = path_only.lstrip("/")                                                                      #stripping leading slashes
    full_path = os.path.join(docroot, rel_path)                                                           #resolving path inside docroot

    if os.path.isdir(full_path) or path_only.endswith("/"):                                               #directory maps to index.html
        full_path = os.path.join(full_path, "index.html")

    #................................................cnd 4: file existence check...................................
    if not os.path.isfile(full_path):
        return 404, "Not Found", {"Content-Type": "text/html"}, error_body(404, "Not Found")

    #................................................cnd 5: reading file content...................................   
    try:
        with open(full_path, "rb") as f:
            content = f.read()
        ctype = get_content_type(full_path)
        return 200, "OK", {"Content-Type": ctype}, content
    except Exception:
        return 404, "Not Found", {"Content-Type": "text/html"}, error_body(404, "Not Found")


#.....................................function to process connection...............................
def process_connection(conn: TCPConnection, docroot: str) -> None:
    head_buf = bytearray()
    head_delimiter = b"\r\n\r\n"
    deadline = time.monotonic() + 10.0                                                                     #strict 10s deadline for total request head

    try:
        while head_delimiter not in head_buf:
            rem = deadline - time.monotonic()
            if rem <= 0:
                conn.close()
                return
            chunk = conn.recv(4096, timeout=rem)                                                           #reading with remaining head time
            if not chunk:
                break
            head_buf.extend(chunk)

        if head_delimiter not in head_buf:
            conn.close()
            return

        idx = head_buf.find(head_delimiter)
        request_head = bytes(head_buf[:idx])

        status_code, reason, headers, body = handle_request(request_head, docroot)

        if "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))                                                     #setting content length header
        headers["Connection"] = "close"                                                                    #closing after response

        first_line = request_head.decode("iso-8859-1", errors="replace").split("\r\n")[0]
        req_method = first_line.split(" ")[0] if " " in first_line else ""
        if req_method == "HEAD":
            body = b""                                                                                     #stripping body for HEAD

        header_lines = [f"HTTP/1.1 {status_code} {reason}"]
        for k, v in headers.items():
            header_lines.append(f"{k}: {v}")
        header_str = "\r\n".join(header_lines) + "\r\n\r\n"

        response_bytes = header_str.encode("iso-8859-1") + body
        conn.send(response_bytes)                                                                           #sending full response

    except (TimeoutError, TCPError):
        pass
    except Exception as e:
        sys.stderr.write(f"Server connection error: {e}\n")
    finally:
        conn.close()                                                                                        #tearing down connection


#..............................................main function........................................
def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP Server over raw TCP sockets")
    parser.add_argument("-p", "--port", dest="port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("-d", "--docroot", dest="docroot", default="./www", help="Document root (default: ./www)")
    parser.add_argument("--log", dest="logfile", default=None, help="Packet log file")

    args = parser.parse_args()

    sock = None
    logger = None
    try:
        sock = RawSocket()                                                                                 #raw socket setup
        logger = PacketLogger(args.logfile)                                                                #logger setup

        while True:
            try:
                conn = TCPConnection(sock, "", args.port, logger)                                          #listening connection
                accepted = conn.accept()                                                                   #waiting for syn handshake
                if accepted:
                    process_connection(conn, args.docroot)                                                 #serving client request
            except Exception:
                continue

    except KeyboardInterrupt:
        return 0
    finally:
        if logger is not None:
            logger.close()
        if sock is not None:
            sock.close()


#.............................................entry point...........................................
if __name__ == "__main__":
    sys.exit(main())

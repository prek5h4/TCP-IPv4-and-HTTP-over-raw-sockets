# COL334 Assignment 3: TCP/IPv4 and HTTP over Raw Sockets

## Team Members
- **Kesar Deval Shah** : 2024CS10132
- **Preksha Rathal** : 2024CS50987

## 1. Overview

This assignment implements a basic TCP/IPv4 transport layer and an HTTP client-server system using raw sockets in Python. The implementation handles TCP connection setup and termination, reliable data transfer, retransmissions, out-of-order packets, and TCP Reno congestion control.

The HTTP client can request files from an HTTP server, while the server handles requests and serves files from its document root. The implementation uses Python's standard library without third-party networking or HTTP packages.

## 2. Language and Requirements

- **Language:** Python 3
- **Target environment:** Ubuntu 22.04 LTS (x86-64 or ARM64)
- **Python version:** Python 3.10 or later
- **Dependencies:** Python standard library only

The programs use modules such as `socket`, `struct`, `select`, `argparse`, `time`, `random`, `dataclasses`, `enum`, `os`, and `sys`.

No compilation or package installation is required. Since raw sockets are used, the client and server should be launched with root privileges.

## 3. File Structure

The submission ZIP is organized as follows:

```text
A3_2024CS10132_2024CS50987.zip
├── client/
│   └── run-client          # Client launcher
├── server/
│   └── run-server          # Server launcher
├── src/
│   ├── client.py           # HTTP client
│   ├── server.py           # HTTP server
│   ├── tcp.py              # TCP connection and data transfer
│   ├── packet.py           # IPv4/TCP packet construction and parsing
│   ├── rawsock.py          # Raw socket interface
│   ├── congestion.py       # TCP Reno congestion control
│   └── pktlog.py           # Packet logging
├── netcfg/
│   ├── client.sh           # Client network configuration
│   ├── r1.sh               # Router R1 configuration
│   ├── r2.sh               # Router R2 configuration
│   └── server.sh           # Server network configuration
├── README.md
└── report.pdf
```

## 4. Network Configuration

The scripts in `netcfg/` configure the IP addresses, routing tables, forwarding settings, and reverse-path filtering for the four virtual machines.

Run the appropriate command on each freshly booted VM, replacing the interface placeholders with the actual interface names.

**Client VM**
```bash
sudo bash netcfg/client.sh <IF_A> <IF_D>
```

**Router R1**
```bash
sudo bash netcfg/r1.sh <IF_A> <IF_B>
```

**Router R2**
```bash
sudo bash netcfg/r2.sh <IF_B> <IF_C> <IF_D>
```

**Server VM**
```bash
sudo bash netcfg/server.sh <IF_C>
```

## 5. Running the Programs

### HTTP Server

On the server VM, run:

```bash
sudo ./server/run-server
```

The server listens on port `8080` by default and serves files from `./www`.

Optional arguments can be used to change the port, document root, or log file:

```bash
sudo ./server/run-server -p PORT -d DOCROOT --log LOGFILE
```

### HTTP Client

On the client VM, run:

```bash
sudo ./client/run-client http://10.10.3.10:8080/large_file.bin -o output.bin
```

The client downloads the requested file and saves it to the specified output path. The `--log LOGFILE` option can be used to record packet or connection logs.

General usage:

```bash
sudo ./client/run-client URL [-o OUTFILE] [--log LOGFILE]
```

## 6. Implementation Details

The implementation is divided into modules, with each module handling a specific part of the system.

- **`rawsock.py`** provides the raw IPv4 socket interface used to send and receive TCP packets.
- **`packet.py`** builds and parses IPv4 and TCP headers, calculates Internet checksums, and handles TCP options such as MSS.
- **`tcp.py`** manages the TCP connection lifecycle, including the three-way handshake, acknowledgements, retransmissions, out-of-order buffering, RTT estimation, and connection termination.
- **`congestion.py`** implements TCP Reno congestion control, including slow start, congestion avoidance, fast retransmit, and fast recovery.
- **`pktlog.py`** records packet and connection information in the required log format.
- **`client.py`** parses URLs, sends HTTP requests, and processes responses using `Content-Length` or chunked transfer encoding.
- **`server.py`** handles HTTP requests and serves static files. It also includes MIME-type detection, path validation, HTTP error responses, and a request timeout.

The launcher scripts in `client/` and `server/` provide the entry points for running the programs.

## 7. Build Instructions

Since the entire implementation is written in Python 3, no compilation or build step is required. The launcher scripts `client/run-client` and `server/run-server` execute the Python source code directly via the standard Python runtime without any external dependencies.


#!/usr/bin/env python3
"""
run_server_test.py - Launch concurrent test servers for T14 Fairness Testing.
Usage:
    sudo python3 test_fairness/run_server_test.py
"""

import os
import sys
import time
import signal
import subprocess

TEST_FILE_MB = 5
DOCROOT = os.path.abspath("www")
TEST_FILE = os.path.join(DOCROOT, "test.bin")

def setup_iptables():
    """Ensure kernel RSTs are dropped during raw socket testing."""
    cmd_check = ["iptables", "-C", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
    cmd_add = ["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
    if subprocess.run(cmd_check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        print("[*] Adding iptables rule to drop outgoing kernel RSTs...")
        subprocess.run(cmd_add)

def prepare_test_file():
    """Creates a 5MB test file in ./www/test.bin."""
    os.makedirs(DOCROOT, exist_ok=True)
    if not os.path.exists(TEST_FILE) or os.path.getsize(TEST_FILE) != TEST_FILE_MB * 1024 * 1024:
        print(f"[*] Generating {TEST_FILE_MB}MB test file at {TEST_FILE}...")
        with open(TEST_FILE, "wb") as f:
            f.write(os.urandom(TEST_FILE_MB * 1024 * 1024))
    print(f"[✓] Test file ready: {TEST_FILE} ({os.path.getsize(TEST_FILE)} bytes)")

def main():
    if os.geteuid() != 0:
        print("Error: Please run with sudo (required for raw sockets and iptables).")
        sys.exit(1)

    setup_iptables()
    prepare_test_file()

    procs = []

    def cleanup(sig=None, frame=None):
        print("\n[*] Stopping all test servers...")
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=1.0)
            except Exception:
                p.kill()
        print("[✓] All servers stopped. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("\n[*] Launching servers...")

    # 1. Custom server on 8080
    p1 = subprocess.Popen(["./server/run-server", "-p", "8080", "-d", DOCROOT])
    procs.append(p1)
    print("  [✓] Custom server started on port 8080")

    # 2. Custom server on 8081
    p2 = subprocess.Popen(["./server/run-server", "-p", "8081", "-d", DOCROOT])
    procs.append(p2)
    print("  [✓] Custom server started on port 8081")

    # 3. Standard Python HTTP server on 8000
    p3 = subprocess.Popen([sys.executable, "-m", "http.server", "8000", "--directory", DOCROOT],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p3)
    print("  [✓] Standard HTTP server started on port 8000")

    # 4. Standard Python HTTP server on 8001
    p4 = subprocess.Popen([sys.executable, "-m", "http.server", "8001", "--directory", DOCROOT],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p4)
    print("  [✓] Standard HTTP server started on port 8001")

    print("\n" + "="*60)
    print("  ALL 4 SERVERS RUNNING! Waiting for Client VM requests...")
    print("  Press Ctrl+C to stop all servers when finished.")
    print("="*60 + "\n")

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()

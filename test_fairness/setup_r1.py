#!/usr/bin/env python3
"""
setup_r1.py - Configure delay on Router R1 for T14 Fairness Testing.
Usage:
    sudo python3 setup_r1.py [IF_B]
    sudo python3 setup_r1.py --clean [IF_B]
"""

import sys
import subprocess
import re

def find_interface_by_ip(subnet_prefix="10.10.2."):
    """Finds the network interface with IP in 10.10.2.x subnet."""
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True)
        for line in out.splitlines():
            # Format: 3: enp0s2 inet 10.10.2.1/24 ...
            parts = line.split()
            if len(parts) >= 4 and subnet_prefix in parts[3]:
                return parts[1]
    except Exception as e:
        print(f"Warning: could not auto-detect interface: {e}")
    return None

def main():
    clean_mode = "--clean" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--clean"]

    iface = args[0] if args else find_interface_by_ip("10.10.2.")
    if not iface:
        print("Error: Could not auto-detect LAN B interface (10.10.2.1).")
        print("Usage: sudo python3 setup_r1.py [IF_B]")
        sys.exit(1)

    print(f"[*] Router R1 - Target Interface: {iface} (LAN B)")

    if clean_mode:
        print(f"[*] Removing tc rules on {iface}...")
        subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], stderr=subprocess.DEVNULL)
        print("[✓] R1 traffic control rules cleared.")
        return

    # Clear existing rules
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], stderr=subprocess.DEVNULL)

    # Add 10ms netem delay
    cmd = ["tc", "qdisc", "add", "dev", iface, "root", "netem", "delay", "10ms"]
    res = subprocess.run(cmd)
    if res.returncode == 0:
        print(f"[✓] Successfully added 10ms delay on R1 ({iface}).")
    else:
        print(f"[!] Failed to configure tc on {iface}. Ensure running with sudo.")
        sys.exit(res.returncode)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
setup_r2.py - Configure 10 Mbit/s, 10ms delay, 30-packet buffer on Router R2 (Link D).
Usage:
    sudo python3 setup_r2.py [IF_D]
    sudo python3 setup_r2.py --clean [IF_D]
"""

import sys
import subprocess

def find_interface_by_ip(subnet_prefix="10.10.4."):
    """Finds the network interface with IP in 10.10.4.x subnet."""
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and subnet_prefix in parts[3]:
                return parts[1]
    except Exception as e:
        print(f"Warning: could not auto-detect interface: {e}")
    return None

def main():
    clean_mode = "--clean" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--clean"]

    iface = args[0] if args else find_interface_by_ip("10.10.4.")
    if not iface:
        print("Error: Could not auto-detect Link D interface (10.10.4.1).")
        print("Usage: sudo python3 setup_r2.py [IF_D]")
        sys.exit(1)

    print(f"[*] Router R2 - Target Interface: {iface} (Link D)")

    if clean_mode:
        print(f"[*] Removing tc rules on {iface}...")
        subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], stderr=subprocess.DEVNULL)
        print("[✓] R2 traffic control rules cleared.")
        return

    # Clear existing rules
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], stderr=subprocess.DEVNULL)

    # 1. Root TBF: 10 Mbit/s, 32k burst, 45000 byte queue (~30 packets)
    cmd1 = ["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "tbf",
            "rate", "10mbit", "burst", "32k", "limit", "45000"]
    res1 = subprocess.run(cmd1)
    if res1.returncode != 0:
        print(f"[!] Failed to configure TBF on {iface}. Ensure running with sudo.")
        sys.exit(res1.returncode)

    # 2. Child netem: 10ms delay
    cmd2 = ["tc", "qdisc", "add", "dev", iface, "parent", "1:1", "netem", "delay", "10ms"]
    res2 = subprocess.run(cmd2)
    if res2.returncode != 0:
        print(f"[!] Failed to configure netem child on {iface}.")
        sys.exit(res2.returncode)

    print(f"[✓] Successfully configured bottleneck on R2 ({iface}):")
    print(f"    - Bandwidth: 10 Mbit/s")
    print(f"    - Delay: 10 ms")
    print(f"    - Queue buffer: ~30 packets (45000 bytes)")

if __name__ == "__main__":
    main()

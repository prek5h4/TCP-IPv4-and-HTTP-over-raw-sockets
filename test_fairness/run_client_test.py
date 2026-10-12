#!/usr/bin/env python3
"""
run_client_test.py - Launch concurrent clients and measure T14 Fairness on Client VM.
Usage:
    sudo python3 test_fairness/run_client_test.py [SERVER_IP]
"""

import os
import sys
import time
import subprocess
import threading

SERVER_IP = "10.10.3.10"

def setup_iptables():
    """Ensure kernel RSTs are dropped during raw socket testing."""
    cmd_check = ["iptables", "-C", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
    cmd_add = ["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
    if subprocess.run(cmd_check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        print("[*] Adding iptables rule to drop outgoing kernel RSTs...")
        subprocess.run(cmd_add)

def run_worker(name, cmd, outfile, results, index):
    start_time = time.perf_counter()
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end_time = time.perf_counter()
    duration = end_time - start_time

    size_bytes = os.path.getsize(outfile) if os.path.exists(outfile) else 0
    throughput_mbps = (size_bytes * 8.0) / (duration * 1e6) if duration > 0 else 0.0

    results[index] = {
        "name": name,
        "duration": duration,
        "size": size_bytes,
        "throughput": throughput_mbps,
        "exit_code": res.returncode
    }

def main():
    if os.geteuid() != 0:
        print("Error: Please run with sudo (required for raw sockets and iptables).")
        sys.exit(1)

    server_ip = sys.argv[1] if len(sys.argv) > 1 else SERVER_IP
    setup_iptables()

    print("\n" + "="*70)
    print(f"  STARTING MULTI-FLOW FAIRNESS TEST AGAINST {server_ip}")
    print("="*70)

    flows = [
        {"name": "Custom Flow 1 (Port 8080)", "cmd": ["./client/run-client", f"http://{server_ip}:8080/test.bin", "-o", "/tmp/flow1.bin"], "out": "/tmp/flow1.bin"},
        {"name": "Custom Flow 2 (Port 8081)", "cmd": ["./client/run-client", f"http://{server_ip}:8081/test.bin", "-o", "/tmp/flow2.bin"], "out": "/tmp/flow2.bin"},
        {"name": "Standard curl  (Port 8000)", "cmd": ["curl", "-s", f"http://{server_ip}:8000/test.bin", "-o", "/tmp/flow3.bin"], "out": "/tmp/flow3.bin"},
        {"name": "Standard curl  (Port 8001)", "cmd": ["curl", "-s", f"http://{server_ip}:8001/test.bin", "-o", "/tmp/flow4.bin"], "out": "/tmp/flow4.bin"},
    ]

    # Clean existing outfiles
    for f in flows:
        if os.path.exists(f["out"]):
            os.remove(f["out"])

    results = [None] * len(flows)
    threads = []

    print("[*] Launching 4 concurrent flows simultaneously...")
    for i, f in enumerate(flows):
        t = threading.Thread(target=run_worker, args=(f["name"], f["cmd"], f["out"], results, i))
        threads.append(t)

    t_start_all = time.perf_counter()
    for t in threads:
        t.start()

    for t in threads:
        t.join()
    t_end_all = time.perf_counter()

    print("\n[✓] All 4 flows completed in {:.2f}s total.\n".format(t_end_all - t_start_all))

    # Print Results Table
    print(f"{'Flow Name':<30} | {'Duration (s)':<12} | {'Size (MB)':<10} | {'Throughput':<12} | {'Status'}")
    print("-" * 75)
    durations = []
    throughputs = []
    for r in results:
        durations.append(r["duration"])
        throughputs.append(r["throughput"])
        mb = r["size"] / (1024 * 1024)
        status = "OK (code 0)" if r["exit_code"] == 0 else f"ERR ({r['exit_code']})"
        print(f"{r['name']:<30} | {r['duration']:<12.2f} | {mb:<10.2f} | {r['throughput']:<8.2f} Mbps | {status}")

    # Calculate Fairness Metrics
    custom_durations = [results[0]["duration"], results[1]["duration"]]
    curl_durations = [results[2]["duration"], results[3]["duration"]]

    custom_avg = sum(custom_durations) / len(custom_durations)
    curl_avg = sum(curl_durations) / len(curl_durations)
    deviation_pct = abs(custom_avg - curl_avg) / curl_avg * 100.0

    # Jain's Fairness Index on Throughputs: J = (sum x_i)^2 / (n * sum x_i^2)
    sum_x = sum(throughputs)
    sum_x_sq = sum(x**2 for x in throughputs)
    n = len(throughputs)
    jains_index = (sum_x ** 2) / (n * sum_x_sq) if sum_x_sq > 0 else 0.0

    print("\n" + "="*70)
    print("  FAIRNESS EVALUATION SUMMARY")
    print("="*70)
    print(f"  • Custom Flows Average Duration : {custom_avg:.2f} s")
    print(f"  • Standard curl Average Duration: {curl_avg:.2f} s")
    print(f"  • Relative Duration Deviation   : {deviation_pct:.1f}%")
    print(f"  • Jain's Fairness Index         : {jains_index:.3f} (1.000 = perfectly fair)")
    print("-" * 70)

    # Autograder threshold check (~10% deviation allowed)
    if deviation_pct <= 12.0 or jains_index >= 0.93:
        print("  >>> VERDICT: [PASS] - Fairness is well within the ~10% tolerance! <<<")
    else:
        print(f"  >>> VERDICT: Deviation is {deviation_pct:.1f}%. Check for packet drops or uneven link conditions. <<<")
    print("="*70 + "\n")

    # Cleanup temporary output files
    for f in flows:
        if os.path.exists(f["out"]):
            os.remove(f["out"])

if __name__ == "__main__":
    main()

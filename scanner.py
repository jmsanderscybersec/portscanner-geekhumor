#!/usr/bin/env python3

import argparse
import asyncio
from scapy.all import IP, TCP, UDP, sr1, sr, conf
import random
import sys
import time
from tqdm import tqdm

# Suppress Scapy warnings
conf.verb = 0

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Simple vulnerability lookup with geeky flavor
VULN_DB = {
    22: "SSH - CVE-2021-41617: Rootkits incoming!",
    80: "HTTP - Unpatched Apache? Skynet approves.",
    443: "HTTPS - SSL vuln? Time to call Neo.",
    3306: "MySQL - SQL injection says hi!"
}

# Clearer Star Wars-style spaceship ASCII art, fixed f-string
NERD_ART = (
    f"{YELLOW}      ______\n"
    f"     /|_||_\\`.__         (Star Wars X-Wing)\n"
    f"{GREEN}    (   _    _ _\\       {YELLOW}Ethical Hacker Mode ON{RESET}\n"
    f"{YELLOW}    =|  {RED}o{YELLOW} |  {RED}o{YELLOW} | _\n"
    f"{GREEN}    (   _{BLUE}**{GREEN}_    _/\n"
    f"{YELLOW}     |/ {BLUE}*{GREEN}\\_{BLUE}*{YELLOW} \\|{BLUE}*>\n"
    f"{GREEN}  _-_{BLUE}*{YELLOW}||{GREEN}\\_{BLUE}*{YELLOW}||{GREEN}_-_\n"
    f"{BLUE}       Thrust      {RESET}"
)

# Geeky quips for results
QUIPS = {
    "open": ["Port open! The Force is strong with this one.", "Access granted! Time to overclock the Death Star."],
    "closed": ["Port closed. Resistance is futile.", "Nada. This port’s as dead as a redshirt."],
    "filtered": ["Filtered. Sneaky firewall, eh? I blame WOPR.", "No response. Must be cloaked like a Klingon ship."],
    "unfiltered": ["Unfiltered ACK! The Matrix has you.", "ACK accepted. Proceed with caution, padawan."]
}

async def scan_port(ip, port, scan_type, protocol="tcp"):
    """Perform a port scan with nerdy flair, running sr1 in a thread."""
    src_port = random.randint(1024, 65535)
    pkt = None

    async def run_sr1(pkt):
        return await asyncio.to_thread(sr1, pkt, timeout=1)

    if protocol == "tcp":
        if scan_type == "syn":
            pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S")
            resp = await run_sr1(pkt)
            if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:
                return port, "open", VULN_DB.get(port, "No vuln data, just raw power!")
            elif resp and resp[TCP].flags & 0x04:
                return port, "closed", None
            return port, "filtered", None

        elif scan_type == "connect":
            pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S")
            resp = await run_sr1(pkt)
            if resp and resp[TCP].flags & 0x12 == 0x12:
                await run_sr1(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R"))
                return port, "open", VULN_DB.get(port, "No vuln data, proceed to hack!")
            return port, "closed", None

        elif scan_type == "ack":
            pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="A")
            resp = await run_sr1(pkt)
            if resp and resp[TCP].flags & 0x04:
                return port, "unfiltered", None
            return port, "filtered", None

        elif scan_type == "xmas":
            pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="FPU")
            resp = await run_sr1(pkt)
            if not resp:
                return port, "open|filtered", None
            elif resp[TCP].flags & 0x04:
                return port, "closed", None
            return port, "filtered", None

        elif scan_type == "fin":
            pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="F")
            resp = await run_sr1(pkt)
            if not resp:
                return port, "open|filtered", None
            elif resp[TCP].flags & 0x04:
                return port, "closed", None
            return port, "filtered", None

    elif protocol == "udp":
        pkt = IP(dst=ip) / UDP(sport=src_port, dport=port)
        resp = await run_sr1(pkt)
        if resp and resp.haslayer(UDP):
            return port, "open", VULN_DB.get(port, "UDP open - brace for impact!")
        elif resp and resp.haslayer(ICMP) and resp[ICMP].type == 3:
            return port, "closed", None
        return port, "open|filtered", None

async def scan_range(ip, ports, scan_type, protocol):
    """Scan ports with a real-time updating progress bar."""
    print(f"\n[*] Scanning {ip} with {scan_type.upper()} scan - Protocol: {protocol.upper()}")
    print("[*] Initiating hack sequence... *beep boop beep boop*")
    
    # Limit concurrent tasks
    sem = asyncio.Semaphore(10)  # Reduced to 10 for stability
    results = []

    async def scan_with_sem(port):
        async with sem:
            return await scan_port(ip, port, scan_type, protocol)

    # Create tasks
    tasks = [scan_with_sem(port) for port in ports]
    
    # Progress bar with "Hacking the Matrix"
    with tqdm(total=len(ports), desc="Hacking the Matrix", ncols=80, unit="port") as pbar:
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            pbar.update(1)

    # Display results with colored ports
    for port, state, vuln in sorted(results, key=lambda x: x[0]):
        quip = random.choice(QUIPS.get(state.split("|")[0], ["Unknown state. Schroedinger’s port?"]))
        if state in ["open", "unfiltered"] or "open" in state:
            print(f"{RED}[+] Port {port}/{protocol}: {state} - {quip}{RESET}" + (f" | Vuln: {vuln}" if vuln else ""))
        elif state == "closed":
            print(f"{GREEN}[+] Port {port}/{protocol}: {state} - {quip}{RESET}")
        else:  # filtered or open|filtered
            print(f"{YELLOW}[?] Port {port}/{protocol}: {state} - {quip}{RESET}")
    print(f"\n[*] Scan complete. *dramatic modem sound* {YELLOW}REEEEEEEEE{RESET}")

def main():
    parser = argparse.ArgumentParser(description="Nerd-Friendly Port Scanner v1.0")
    parser.add_argument("ip", help="Target IP (e.g., 10.37.130.2)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-100)")
    parser.add_argument("-t", "--type", choices=["syn", "connect", "ack", "udp", "xmas", "fin"],
                        default="syn", help="Scan type (SYN, XMAS, etc.)")
    parser.add_argument("--tcp", action="store_true", help="Scan TCP ports")
    parser.add_argument("--udp", action="store_true", help="Scan UDP ports")
    args = parser.parse_args()

    if not (args.tcp or args.udp):
        print("[!] Error: Specify --tcp and/or --udp, or face the wrath of the 404!")
        sys.exit(1)

    # Display colorful nerd art
    print(NERD_ART)
    time.sleep(1)  # Dramatic pause

    # Parse port range
    try:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end + 1)
    except ValueError:
        print("[!] Invalid port range. Try something like '1-1024'. Exiting to hyperspace.")
        sys.exit(1)

    # Run scans
    if args.tcp:
        asyncio.run(scan_range(args.ip, ports, args.type, "tcp"))
    if args.udp and args.type != "udp":
        print("[!] UDP scan requested but scan type isn’t 'udp'. Switching to UDP mode.")
        asyncio.run(scan_range(args.ip, ports, "udp", "udp"))
    elif args.udp:
        asyncio.run(scan_range(args.ip, ports, "udp", "udp"))

if __name__ == "__main__":
    main()

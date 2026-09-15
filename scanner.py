import argparse
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Completely silence scapy warnings right at startup
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser(description="Zero-Error Local Network Scanner")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address range to scan (e.g., 192.168.2.1/24)")
    options = parser.parse_args()
    return options

def ping_ip(ip):
    """Uses the native Windows ping system to check if an IP is alive."""
    command = ["ping", "-n", "1", "-w", "200", ip]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if "TTL=" in result.stdout:
        return ip
    return None

def get_mac(ip):
    """Safe, single-packet ARP request that won't crash Python 3.14."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    try:
        ans, _ = scapy.srp(packet, timeout=1, verbose=False)
        if ans:
            for snd, rcv in ans:
                return rcv.hwsrc
    except Exception:
        pass
    return "Unknown/Protected"

def scan_network(ip_range):
    print(f"\n[*] Initializing stable scan on target range: {ip_range}")
    print("--------------------------------------------------")
    print("IP Address\t\tMAC Address")
    print("--------------------------------------------------")
    
    try:
        base_net = ".".join(ip_range.split(".")[0:3]) + "."
        ips = [f"{base_net}{i}" for i in range(1, 255)]
    except Exception:
        print("[-] Invalid IP range format. Use a notation like 192.168.2.1/24")
        sys.exit(1)

    active_ips = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_ip, ips)
        for ip in results:
            if ip:
                active_ips.append(ip)

    for ip in active_ips:
        mac = get_mac(ip)
        print(f"{ip}\t\t{mac}")
                
    print("--------------------------------------------------")
    print("[*] Scan complete successfully.")

if __name__ == "__main__":
    args = get_arguments()
    scan_network(args.target)


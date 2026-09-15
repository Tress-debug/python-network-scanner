import argparse
import sys
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor

# We import requests to talk to the MAC vendor API database
import requests

# Completely silence scapy warnings right at startup
logging.getLogger("scapy").setLevel(logging.ERROR)
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser(description="Device Name Detecting Local Network Scanner")
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
    """Safe, single-packet ARP request that looks up physical addresses."""
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

def get_vendor_name(mac_address):
    """Queries a free API database to turn a MAC Address into a Manufacturer Name."""
    if mac_address == "Unknown/Protected":
        return "Unknown Device"
        
    try:
        # We send the MAC address to a public database API to identify the hardware builder
        url = f"https://macvendors.com{mac_address}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return "Generic Device"

def scan_network(ip_range):
    print(f"\n[*] Initializing smart device scan on target range: {ip_range}")
    print("--------------------------------------------------------------------------------")
    print("IP Address\t\tMAC Address\t\tDevice Manufacturer")
    print("--------------------------------------------------------------------------------")
    
    try:
        base_net = ".".join(ip_range.split(".")[0:3]) + "."
        ips = [f"{base_net}{i}" for i in range(1, 255)]
    except Exception:
        print("[-] Invalid IP range format. Use a notation like 192.168.2.1/24")
        sys.exit(1)

    # 1. Swiftly map which IPs are active using multithreaded network pings
    active_ips = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_ip, ips)
        for ip in results:
            if ip:
                active_ips.append(ip)

    # 2. Extract MAC layouts and resolve vendor identities sequentially 
    for ip in active_ips:
        mac = get_mac(ip)
        vendor = get_vendor_name(mac)
        print(f"{ip}\t\t{mac}\t\t{vendor}")
                
    print("--------------------------------------------------------------------------------")
    print("[*] Smart device scan completed successfully.")

if __name__ == "__main__":
    args = get_arguments()
    scan_network(args.target)


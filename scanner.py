import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser(description="Simple Local Network ARP Scanner")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address range to scan (e.g., 192.168.1.1/24)")
    options = parser.parse_args()
    return options

def scan_ip(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = broadcast / arp_request
    answered_list = scapy.srp(arp_request_packet, timeout=2, verbose=False)[0]
    
    if answered_list:
        return {"ip": answered_list[0][1].psrc, "mac": answered_list[0][1].hwsrc}
    return None

def scan_network(ip_range):
    print(f"[*] Starting scan on target range: {ip_range}")
    print("--------------------------------------------------")
    print("IP Address\t\tMAC Address")
    print("--------------------------------------------------")
    
    try:
        ips = [str(ip) for ip in scapy.Net(ip_range)]
    except Exception:
        print("[-] Invalid IP range. Use a format like 192.168.1.1/24")
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(scan_ip, ips)
        for result in results:
            if result:
                print(f"{result['ip']}\t\t{result['mac']}")

if __name__ == "__main__":
    args = get_arguments()
    scan_network(args.target)

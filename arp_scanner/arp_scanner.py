"""
ARP Scanner - Discover devices on your local network and retrieve MAC addresses,
vendor information, and hostnames. Outputs results to console and logs to a file.
"""
import os

import argparse
import socket
import logging
import scapy.all as scapy

#OUI MAP
def load_oui_database():
    """
    Loads the IEEE OUI database from local file.
    Expects 'oui.txt' in the script directory.
    """
    oui_map = {}

    if not os.path.exists(OUI_FILE):
        raise FileNotFoundError("OUI file not found. Please download 'oui.txt' manually from IEEE.")

    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if "(hex)" in line:
                parts = line.strip().split("(hex)")
                oui = parts[0].strip().replace("-", ":")
                vendor = parts[1].strip()
                oui_map[oui] = vendor

    return oui_map


OUI_FILE = "oui.txt"


# -------------------------------
# Argument Parsing
# -------------------------------
def parse_args():
    """
    Parses command-line arguments.

    Returns:
        argparse.Namespace: Object containing 'ip' (target network or host)
    """
    parser = argparse.ArgumentParser(
        description="Scan MAC addresses of devices on the network."
    )

    parser.add_argument(
        "ip",
        default="",
        help="Target IP address or CIDR range (e.g., 192.168.1.0/24)"
    )

    return parser.parse_args()


# -------------------------------
# Helper Functions
# -------------------------------
def resolve_hostname(ip):
    """
    Attempts reverse DNS lookup to resolve the hostname of a given IP.

    Args:
        ip (str): Target IP address

    Returns:
        str: Hostname if resolved, otherwise 'Unknown'
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.timeout):
        return "Unknown"


def lookup_vendor(mac):
    """
    Looks up vendor information from MAC address using the OUI map.

    Args:
        mac (str): MAC address of the device

    Returns:
        str: Vendor name if found, otherwise 'Unknown'
    """
    oui = mac.upper()[0:8]  # First 3 bytes represent the vendor
    return OUI_MAP.get(oui, "Unknown")


# -------------------------------
# Logging Configuration
# -------------------------------
logging.basicConfig(
    filename="arp_scan.log",                 # Log file path
    filemode="w",                            # Overwrite log on each run; use "a" to append
    format="%(asctime)s - %(message)s",      # Include timestamp
    level=logging.INFO                        # Log level
)


# -------------------------------
# ARP Scan Function
# -------------------------------
def arp_scan(target_ip):
    """
    Performs an ARP scan on the target network or host range.

    Args:
        target_ip (str): Target IP or CIDR range to scan

    Returns:
        list: List of discovered devices with IP, MAC, vendor, and hostname
    """
    devices = []  # List to store discovered devices

    # Create an Ethernet frame with broadcast destination
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # pylint: disable=no-member

    # Create an ARP request packet targeting the specified IP range
    arp = scapy.ARP(pdst=target_ip)  # pylint: disable=no-member

    # Combine Ethernet and ARP layers into a single packet
    packet = ether / arp

    # Send the packet and wait for responses (srp = send & receive at Layer 2)
    answered, _ = scapy.srp(packet, timeout=2, verbose=False)

    # Parse responses and store device info
    for _, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": lookup_vendor(received.hwsrc),
            "hostname": resolve_hostname(received.psrc)
        })

    return devices


# -------------------------------
# Main Execution
# -------------------------------
if __name__ == "__main__":
    args = parse_args()
    OUI_MAP = load_oui_database()

    if not args.ip:
        print("Please specify a target IP address or network range.")
        sys.exit(1)

    # Perform ARP scan
    detected_devices = arp_scan(args.ip)

    if not detected_devices:
        print("No devices found.")
        sys.exit(0)

    # Print header with aligned columns
    print(f"{'IP Address':<16} {'MAC Address':<18} {'Hostname':<30} {'Vendor':<15} ")
    print("-" * 100)

    # Display results and log each device
    for d in detected_devices:
        output_line = f"{d['ip']:<16} {d['mac']:<18} {d['hostname']:<30} {d['vendor']:<15}"
        print(output_line)
        logging.info(output_line)

    # Log and display summary
    logging.info(f"Total devices discovered: {len(detected_devices)}")
    print(f"\nTotal devices discovered: {len(detected_devices)}")

# ARP Scanner

> **WARNING: EDUCATIONAL USE ONLY**  
> Scan only networks you own or have explicit permission to test.

A simple Python ARP scanner that discovers devices on a local network and displays their IP address, MAC address, hostname, and vendor information.

---

## Features

- ARP scan of a host or CIDR range
- Displays IP, MAC, hostname, and vendor
- Vendor lookup via IEEE OUI database
- Logs results to `arp_scan.log`
- Clean console output

---

## Requirements

- Python 3.8+
- Root / Administrator privileges
- `scapy`

Install dependencies:
```bash
pip install scapy
```

## OUI Database

- This program requires the IEEE OUI database.
- Download oui.txt from the IEEE website or from this repo.
- Place it in the same directory as the script
- The program will exit if the file is missing.

## Usage
```bash
python arpscanner.py <target>
```

Examples:
```bash
python arpscanner.py 192.168.1.0/24
python arpscanner.py 192.168.1.1


IP Address       MAC Address        Hostname                      Vendor
----------------------------------------------------------------------------------------------------
192.168.1.1      AA:BB:CC:DD:EE:FF  router.local                  Cisco Systems
192.168.1.25     11:22:33:44:55:66  Unknown                       Apple, Inc.

Total devices discovered: 2
```

Results are also written to arp_scan.log.

**Notes**

Must be run with elevated privileges
Hostname resolution may return Unknown
Vendor accuracy depends on the OUI database

**Disclaimer**

This tool is for learning and basic network diagnostics only.
Unauthorized network scanning may be illegal.

# Network Scanner

A Python-based network scanner that performs a ping sweep to identify active hosts and scans specified ports for open connections. The tool supports IP ranges, single IP addresses, and hostnames. It features multi-threaded scanning and user-configurable options for delays and ports.

## Features

- **IP Range and Hostname Validation:** Accepts IP ranges (e.g., `192.168.1.0/24`), single IPs (e.g., `192.168.1.1`), and hostnames (e.g., `example.com`).
- **Ping Sweep:** Identifies active hosts within a given range.
- **Port Scanning:** Scans user-specified ports or defaults to common ports (21, 22, 80, 53, 443) on active hosts.
- **Multi-Threaded:** Enhances scanning speed by using multiple threads.
- **Service Name Retrieval:** Displays service names associated with open ports.
- **Configurable Delays:** Set delay between individual port scans and a 5-second delay between scanning different hosts.

## Usage
Technical Details
    Language: Python
    Libraries: scapy, socket, threading, ipaddress
    Protocols: ICMP for ping sweep, TCP for port scanning
Input Prompts:
    Enter an IP range, single IP address, or hostname.
    Specify ports to scan or press Enter to use default ports.
    Set the delay between port scans.

1. **Install Dependencies:**
   Ensure you have Python installed, then install required libraries:
   ```bash
   pip install scapy
2. **Run the Scanner:**
Execute the script and follow the prompts:
  ```bash
   sudo python3 networkscanner.py









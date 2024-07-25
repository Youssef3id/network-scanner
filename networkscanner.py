import scapy.all as scapy
import socket
import threading
import time
from ipaddress import ip_network, ip_address

def validate_input(ip_range_or_host):
    """
    Validate and adjust the input to ensure it's a proper network address, single IP, or hostname.
    """
    try:
        if '/' in ip_range_or_host:
            network = ip_network(ip_range_or_host, strict=False)
            return network, 'network'
        else:
            ip = ip_address(ip_range_or_host)
            return [ip], 'ip'
    except ValueError:
        try:
            ip = socket.gethostbyname(ip_range_or_host)
            return [ip_address(ip)], 'host'
        except socket.gaierror:
            print(f"Invalid input: {ip_range_or_host}")
            return None, None

def ping_sweep(ips):
    """
    Function to perform a ping sweep over a given list of IPs.
    """
    active_hosts = []
    for ip in ips:
        icmp_request = scapy.IP(dst=str(ip))/scapy.ICMP()
        response = scapy.sr1(icmp_request, timeout=1, verbose=False)
        if response:
            print(f"Host {ip} is up")
            active_hosts.append(str(ip))
    return active_hosts

def get_service_name(port):
    """
    Function to get the service name for a given port using socket.
    """
    try:
        service = socket.getservbyport(port)
    except OSError:
        service = "Unknown"
    return service

def scan_port(ip, port, delay, results):
    """
    Function to scan a single port on a given IP address.
    """
    ip_str = str(ip)  # Convert IPAddress to string
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((ip_str, port))
    if result == 0:
        service = get_service_name(port)
        results.append((port, service))
    sock.close()
    time.sleep(delay)

def port_scanner(ip, ports, delay):
    """
    Function to scan ports on a given IP address using multiple threads.
    """
    results = []
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(ip, port, delay, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    return results

if __name__ == "__main__":
    ip_range_or_host = input("Enter IP range, single IP address, or hostname (e.g., 192.168.1.0/24, 192.168.1.1, example.com): ")
    targets, target_type = validate_input(ip_range_or_host)

    if targets:
        if target_type == 'network':
            active_hosts = ping_sweep(targets)
        else:
            active_hosts = targets

        if active_hosts:
            ports_input = input("Enter ports to scan (space separated, e.g., 21 22 23 80 443) or press Enter to use default ports: ")
            if not ports_input.strip():  # If no ports are provided
                ports = [21, 22, 80, 53, 443]  # Default ports
            else:
                ports = [int(port.strip()) for port in ports_input.split()]

            delay = float(input("Enter delay between port scans (in seconds): "))

            for host in active_hosts:
                print(f"\nScanning ports on {host}...")
                open_ports = port_scanner(host, ports, delay)
                if open_ports:
                    for port, service in open_ports:
                        print(f"Open port {port} ({service}) on {host}")
                else:
                    print(f"No open ports found on {host}")

                # 5 seconds delay between scanning different hosts
                time.sleep(5)
        else:
            print("No active hosts found.")
    else:
        print("Invalid input provided.")

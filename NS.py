import socket
import threading
import subprocess
import ipaddress
import logging
import platform
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(filename="network_scanner.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")


# Cross-platform ping sweep
def ping_sweep(network):
    print("Starting Ping Sweep...")
    live_hosts = []
    os_name = platform.system().lower()
    ping_cmd = ['ping', '-c', '1', '-W', '1'] if os_name != 'windows' else ['ping', '-n', '1', '-w', '1000']

    try:
        for ip in ipaddress.IPv4Network(network, strict=False):
            response = subprocess.run(ping_cmd + [str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = response.stdout.decode('utf-8')
            if "TTL" in output or "Reply from" in output:
                live_hosts.append(str(ip))
                print(f"{ip} is online")
                logging.info(f"{ip} is online")
    except Exception as e:
        logging.error(f"Error during ping sweep: {e}")
    return live_hosts


# Port scanning function with proper threading
def port_scan(ip, start_port, end_port):
    print(f"Scanning ports on {ip}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Increase timeout to 1 second
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is open on {ip}")
                logging.info(f"Port {port} is open on {ip}")
            else:
                print(f"Port {port} is closed on {ip}")  # Log closed ports
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port} on {ip}: {e}")
    if not open_ports:
        print(f"No open ports found on {ip} in the range {start_port}-{end_port}.")
    return open_ports


# MAC Address Retrieval
def get_mac_address(ip):
    try:
        response = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response.returncode == 0:
            lines = response.stdout.decode('utf-8').splitlines()
            for line in lines:
                if ip in line:
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
        return "Unknown"
    except Exception as e:
        logging.error(f"Error getting MAC address for {ip}: {e}")
        return "Unknown"


# Service Detection
def detect_services(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Timeout for connection
            result = sock.connect_ex((ip, port))
            
            # If connection was successful, try to get the service banner
            if result == 0:
                print(f"Connection successful on {ip}:{port}. Attempting service detection...")
                
                # Try to get a banner based on common services
                banner = ""
                
                # Check for HTTP (port 80, 443, etc.)
                if port == 80 or port == 443:
                    sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                    banner = sock.recv(1024).decode(errors='ignore')
                
                # Check for FTP (port 21)
                elif port == 21:
                    sock.send(b"USER anonymous\r\n")
                    banner = sock.recv(1024).decode(errors='ignore')
                
                # Check for SSH (port 22)
                elif port == 22:
                    sock.send(b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n")  # Generic banner
                    banner = sock.recv(1024).decode(errors='ignore')
                
                # Check for SMTP (port 25)
                elif port == 25:
                    sock.send(b"EHLO example.com\r\n")
                    banner = sock.recv(1024).decode(errors='ignore')
                
                # Check for POP3 (port 110)
                elif port == 110:
                    sock.send(b"USER test\r\n")
                    banner = sock.recv(1024).decode(errors='ignore')
                
                # Check for IMAP (port 143)
                elif port == 143:
                    sock.send(b"A1 LOGIN test test\r\n")
                    banner = sock.recv(1024).decode(errors='ignore')
                
                # If banner exists, print it
                if banner:
                    print(f"Service on {ip}:{port} - {banner.strip()}")
                    logging.info(f"Service on {ip}:{port} - {banner.strip()}")
                else:
                    print(f"No banner retrieved for service on {ip}:{port}")
                    logging.info(f"No banner retrieved for service on {ip}:{port}")
            else:
                print(f"Failed to connect to {ip}:{port}")
                logging.info(f"Failed to connect to {ip}:{port}")
    except Exception as e:
        logging.error(f"Error detecting service on {ip}:{port}: {e}")



# OS Fingerprinting
def os_fingerprint(ip):
    print(f"Performing OS Fingerprinting on {ip}...")
    try:
        response = subprocess.run(['nmap', '-O', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response.returncode == 0:
            os_info = [line for line in response.stdout.decode().splitlines() if "OS details" in line]
            os = os_info[0] if os_info else "Unknown OS"
            print(f"IP: {ip}, OS: {os}")
            logging.info(f"IP: {ip}, OS: {os}")
        else:
            print(f"Could not fingerprint OS for {ip}")
    except Exception as e:
        logging.error(f"Error fingerprinting OS for {ip}: {e}")


# Network Map
def network_map(ip_list):
    print("Generating Network Map...")
    devices = {}
    for ip in ip_list:
        mac = get_mac_address(ip)
        devices[ip] = mac
    print_network_map(devices)


def print_network_map(devices):
    print("IP Addresses\tMAC Addresses")
    for ip, mac in devices.items():
        print(f"{ip}\t{mac}")


# Main Function
def main():
    network = input("Enter the network (e.g., 192.168.1.0/24): ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))

    live_hosts = ping_sweep(network)
    for ip in live_hosts:
        open_ports = port_scan(ip, start_port, end_port)
        for port in open_ports:
            detect_services(ip, port)
        os_fingerprint(ip)
    network_map(live_hosts)


if __name__ == "__main__":
    main()

import subprocess
import socket
import re
from datetime import datetime

port_names = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    179: "BGP",
    830: "Netconf"
}


def get_interfaces():
    """Parse network interfaces, their state and IP from ip address output."""
    command = ["ip", "address"]
    result = subprocess.run(command, capture_output=True, text= True)

    pattern = re.compile(
        r"^\d+:\s+(\S+):.*?state\s+(\S+)(?:.*?inet\s+(\d{1,3}(?:\.\d{1,3}){3}))?",
        re.MULTILINE | re.DOTALL,
    )
    interfaces = []
    matches = pattern.findall(result.stdout)
    for name, state, ip in matches:
        ip = ip if ip else "No IP Assigned"
        interfaces.append({"Interface": name, "State": state, "IP": ip})

    return interfaces

def get_default_gateway():
    """Parse the default gateway and exit interface from 'ip route' output.
        Returns a list of [gateway_ip, interface_name]."""

    command = ["ip", "route"]
    result = subprocess.run(command, capture_output=True, text= True)
    route_pattern = re.compile(r"\bvia\s+(\S+)\s+dev\s+(\S+)")

    default_gateway = []
    for line in result.stdout.splitlines():
        if line.startswith("default"):
            match = route_pattern.search(line)
            if match:
                gateway, interface = match.groups()
                default_gateway = [gateway, interface]


    return default_gateway

def resolve_dns(hosts):
    """Resolve a list of hostnames to IP addresses using getaddrinfo.
    Returns a list of resolved IPs or 'FAILED' for unresolvable hosts."""

    resolved = []
    for host in hosts:
        try:
            ip = socket.getaddrinfo(host, None)[0][4][0]
            resolved.append(ip)
        except socket.gaierror:
            resolved.append("FAILED")

    return resolved

def check_reachability(hosts,resolved):
    """Ping each host and check reachability.
    Returns a list of tuples (hostname, resolved_ip, status) where status is UP, DOWN or UNKNOWN."""

    status = []
    for i, host in enumerate(hosts):
        if resolved[i] != "FAILED":
            command = ["ping", "-c", '1', str(host)]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                status.append((host, resolved[i], "UP"))
            else:
                status.append((host, resolved[i], "CLOSED"))

        else:
            status.append((host, resolved[i], "UNKNOWN"))

    return status

def scan_ports(host, ports):
    """Scan a list of TCP ports on a given host using raw sockets.
    Returns a list of OPEN or CLOSED strings corresponding to each port."""

    open_ports = []
    for port in ports:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            open_ports.append("OPEN")
        else:
            open_ports.append("DOWN")

    return open_ports


def print_report(interfaces, gateway, hosts, ports, port_dict):
    """Print a formatted network diagnostic report to stdout.
    Includes interfaces, gateway, DNS resolution, reachability and port scan results."""

    now = datetime.now()
    print("============ Network Diagnostic Report ============")
    print(f"Generated: {now:%Y-%m-%d %H:%M:%S}\n\n")

    print("--- Interfaces ---")
    num_interfaces = 0
    for interface in interfaces:
        print(f"{interface['Interface']:<10} {interface['State']:<10} {interface['IP']:<10}")
        if interface["State"] == "UP":
            num_interfaces += 1


    print("\n--- Default Gateway ---")
    print(f"Gateway: {gateway[0]}")
    print(f"Interface: {gateway[1]}\n")

    print("--- Reachability and DNS Resolution ---")
    num_hosts = 0
    for host in hosts:
        print(f"{host[0]:<15} -> {host[1]:<39} {host[2]:<5}")
        if host[2] == "UP":
            num_hosts += 1

    print("\n--- Open Ports (local) ---")
    for port in ports:
        print(f"Port: {port:<10} {port_names[port]:<10} {port_dict[port]}")

    print(f"============ Summary ============")
    print(f"Interfaces Up: {num_interfaces}/{len(interfaces)}")
    print(f"DNS: {num_hosts}/{len(hosts)}")


def main():
    """Entry point. Runs all diagnostic checks and prints the final report."""

    interfaces = get_interfaces()
    default_gateway = get_default_gateway()

    hosts = ["google.com", "cloudfare.com", "amazon.com"]

    resolved = resolve_dns(hosts)

    status = check_reachability(hosts, resolved)
    ports = [22,23, 80, 443, 179, 830]
    port_status = scan_ports("127.0.0.1", ports)

    port_dict = dict(zip(ports, port_status))

    print_report(interfaces, default_gateway, status, ports, port_dict)

if __name__ == "__main__":
    main()

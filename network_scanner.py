import argparse
from scapy.all import Ether, ARP, srp, IP, TCP, sr
import socket

def arp_scan(ip):
    """
    Performs a network scan by sending ARP requests to an IP address or a range of IP addresses.

    Args:
        ip (str): An IP address or IP address range to scan. For example:
                    - 192.168.1.1 to scan a single IP address
                    - 192.168.1.1/24 to scan a range of IP addresses.

    Returns:
        list: A list of dictionaries mapping IP addresses to MAC addresses. Example:
        [
            {'IP': '192.168.2.1', 'MAC': 'c4:93:d9:8b:3e:5a'}
        ]
    """
    try:
        # Create the ARP request packet
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        
        # Send the packet and receive responses
        ans, unans = srp(request, timeout=2, retry=1, verbose=False)
        result = []

        for sent, received in ans:
            result.append({'IP': received.psrc, 'MAC': received.hwsrc})

        return result
    except Exception as e:
        print(f"Error: {e}")
        return []


def tcp_scan(ip, ports):
    """
    Performs a TCP scan by sending SYN packets to <ports>.

    Args:
        ip (str): An IP address or hostname to target.
        ports (list or tuple of int): A list or tuple of ports to scan.

    Returns:
        list: A list of open ports.
    """
    try:
        # Resolve IP address
        ip = socket.gethostbyname(ip)
        
        # Create the SYN packet
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
        
        # Send the packet and receive responses
        ans, unans = sr(syn, timeout=2, retry=1, verbose=False)
        result = []

        for sent, received in ans:
            if received.haslayer(TCP) and received[TCP].flags == "SA":
                result.append(received[TCP].sport)

        return result
    except socket.gaierror:
        raise ValueError(f'Hostname {ip} could not be resolved.')
    except Exception as e:
        print(f"Error: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Network scanning tool for ARP and TCP.")
    subparsers = parser.add_subparsers(dest="command", help="Command to perform.", required=True)

    # ARP scan command
    arp_subparser = subparsers.add_parser(
        'ARP', help='Perform a network scan using ARP requests.'
    )
    arp_subparser.add_argument(
        'IP', help='An IP address (e.g., 192.168.1.1) or address range (e.g., 192.168.1.1/24) to scan.'
    )

    # TCP scan command
    tcp_subparser = subparsers.add_parser(
        'TCP', help='Perform a TCP scan using SYN packets.'
    )
    tcp_subparser.add_argument('IP', help='An IP address or hostname to target.')
    tcp_subparser.add_argument(
        'ports', nargs='+', type=int,
        help='Ports to scan, delimited by spaces. When --range is specified, scan a range of ports. Otherwise, scan individual ports.'
    )
    tcp_subparser.add_argument(
        '--range', action='store_true',
        help='Specify a range of ports. When this option is specified, <ports> should be given as <low_port> <high_port>.'
    )

    args = parser.parse_args()

    if args.command == 'ARP':
        result = arp_scan(args.IP)
        if result:
            for mapping in result:
                print(f'{mapping["IP"]} ==> {mapping["MAC"]}')
        else:
            print("No devices found or an error occurred during ARP scan.")

    elif args.command == 'TCP':
        if args.range:
            if len(args.ports) != 2:
                print('Error: When using --range, exactly two ports must be specified.')
                exit(1)
            ports = range(args.ports[0], args.ports[1] + 1)
        else:
            ports = args.ports
        
        try:
            result = tcp_scan(args.IP, ports)
        except ValueError as error:
            print(error)
            exit(1)

        if result:
            for port in result:
                print(f'Port {port} is open.')
        else:
            print('No open ports found or an error occurred during TCP scan.')

if __name__ == '__main__':
    main()

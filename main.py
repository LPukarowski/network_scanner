import argparse
import os
import socket
import threading
import time
from queue import Queue
import sys
import itertools
from colorama import init, Fore
import re

que = Queue()
locking = threading.Lock()

init(autoreset=True)
results = {}


common_ports = {
    20: "FTP-Data", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 53: "DNS", 
    67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 
    119: "NNTP", 123: "NTP", 135: "RPC / MSRPC",
    137: "NetBIOS-Name", 138: "NetBIOS-Datagram", 
    139: "NetBIOS-Session", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 
    443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD/LPR", 520: "RIP", 
    587: "SMTP-Submission", 631: "IPP / CUPS",
    636: "LDAPS", 873: "rsync", 902: "VMware-Server", 
    912: "VMware-VIX", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 
    1434: "MSSQL-Monitor", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2181: "Zookeeper", 
    2375: "Docker", 2376: "Docker TLS",
    2483: "Oracle-DB", 2484: "Oracle-DB TLS", 
    3306: "MySQL", 3389: "RDP", 3478: "STUN",
    3632: "distccd", 4369: "Erlang-PortMapper", 
    5000: "UPnP / Flask", 5432: "PostgreSQL",
    5672: "AMQP / RabbitMQ", 5900: "VNC", 
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    6667: "IRC", 8000: "HTTP-Alt", 8008: "HTTP-Proxy",
    8080: "HTTP-Proxy/Alt", 8081: "HTTP-API", 8443: "HTTPS-Alt", 
    8500: "Consul", 9000: "SonarQube / PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch", 
    9300: "Elasticsearch-Cluster", 9999: "Abyss",
    11211: "Memcached", 27017: "MongoDB", 
    27018: "MongoDB-Cluster", 50000: "SAP",
}

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group_ip = parser.add_mutually_exclusive_group(required=True)

group.add_argument('--quick-scan', '-qs', dest='quick_scan', action='store_true')
group.add_argument('--full-scan', '-fs', dest='full_scan', action='store_true')
group.add_argument('--custom-scan', '-cs', dest='custom_scan', action='store_true')

group_ip.add_argument('--range', '-r', dest='range', action='store_true')
group_ip.add_argument('--single-ip', '-s', dest='single_ip', action='store_true')

parser.add_argument('--threads', '-t', dest='threads', type=int,  
                    default=30 if '--full-scan' in sys.argv or '-fs' in sys.argv else 10)
parser.add_argument('--delay', '-d', dest='delay', type=float,
                    default=0 if '--full-scan' in sys.argv or '-fs' in sys.argv else 0.25)
parser.add_argument('--verbose', '-v', dest='verbose', action='store_true')
parser.add_argument('--logfile', '-l', dest='logfile', type=str)
args = parser.parse_args()

def use_regex(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?$", re.IGNORECASE)
    return pattern.match(input_text)

def known_banner():
    print("=" * 40, "\n")
    print(Fore.MAGENTA + " This scan includes known common ports \n")
    print("=" * 40, "\n")

def ip_range(ele):
    octets = ele.split('.')
    split_octets = list(octet.split('-') for octet in octets)
    ranges = [range(int(i[0]), int(i[1]) + 1) if len(i) == 2 else i for i in split_octets]
    
    for addr in itertools.product(*ranges):
        ip = '.'.join(map(str, addr))
        yield ip
def printout(i):
    for ip in i:
        print(Fore.MAGENTA + f"\nScan results for {ip}:\n")



def worker(delay):

    while not que.empty():
        try:
            ip, port = que.get_nowait()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                except sock.timeout:
                    banner = ''       
                with locking:
                    if ip not in results:
                        results[ip] = []
                    results[ip].append((port, banner))
        except ConnectionRefusedError:
                with locking:
                    if ip not in results:
                        results[ip] = []
                    results[ip].append((port, 'closed'))
        except socket.timeout:
            if args.verbose:
                with locking:
                    print(Fore.YELLOW + f'{port}   timed out\n')

        except Exception as e:
            print(f'Error scanning port {port}: {e}')
        finally:
            sock.close()
            que.task_done()
            time.sleep(delay)


def main():

    ip_active = []

    print("threads:", args.threads)
    print("delay:", args.delay)
    print("logfile:", args.logfile)

    if args.range:
        input_ip = input("\nEnter starting IP (eg.192.168.1-2.1-255): ")
        use_regex(input_ip)
        if not use_regex(input_ip):
            print(Fore.RED, "Invalid IP range format. Use format like 192-193.168.1-2.1-255")
            sys.exit(1)
    else:
        input_ip = input("\nEnter target IP (eg.192.168.1.1): ")

    if args.quick_scan:
        start_port = 1
        end_port = 1024
        known_banner()
        input("\nPress Enter to continue...\n")
    elif args.full_scan:
        start_port = 1
        end_port = 65535
    else:
        start_port = int(input("\nEnter start port: "))
        end_port = int(input("\nEnter end port: "))
        if any(port in common_ports for port in range(start_port, end_port + 1)):
            known_banner()
    
    print(Fore.GREEN, f"\nPinging IPs in the range to check for active hosts...\n")

    for ip in ip_range(input_ip):
       if os.system(f"ping -n 1 {ip} | find \"TTL\" > NUL") == 0:
            ip_active.append(ip)

    print(Fore.GREEN, f"{len(ip_active)} hosts are active.\n")
    for ip in ip_active:
        for port in range(start_port, end_port + 1):
            que.put((ip, port))
    print(Fore.GREEN, f"\nStarting scan active hosts from port {start_port} to {end_port}...\n")
    

    threads = []
    for t in range(args.threads):
        thread = threading.Thread(target=worker, args=(args.delay,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    printout(results)

if __name__ == "__main__":
    main()

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
from tqdm import tqdm

que = Queue()
locking = threading.Lock()

init(autoreset=True)
results = {}
ip_active = []

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
group_file = parser.add_mutually_exclusive_group(required=False)

group.add_argument('--quick-scan', '-qs', dest='quick_scan', action='store_true',
                   help='Scan ports from 0 to 1024')
group.add_argument('--full-scan', '-fs', dest='full_scan', action='store_true',
                   help='Scan ports from 0 to 65535')
group.add_argument('--custom-scan', '-cs', dest='custom_scan',
                   help='Scan custom port range (e.g., 50-5000)')
group.add_argument('--port-list', '-pl', dest='port_list',
                   help='Scan specific ports from a comma-separated list (e.g., 22,80,443)')

group_ip.add_argument('--range', '-r', dest='ipr',
                      help='Specify an IP range to scan (e.g., 192.168.1-2.1-255)')
group_ip.add_argument('--single-ip', '-s', dest='ip',
                      help='Specify a single IP to scan (e.g., 192.168.1.1)')

parser.add_argument('--threads', '-t', dest='threads', type=int,  
                    default=100 if '--full-scan' in sys.argv or '-fs' in sys.argv else 50,
                    help='Number of concurrent threads (default: 50 for custom/quick scan, 100 for full scan)')
parser.add_argument('--delay', '-d', dest='delay', type=float,
                    default=0 if '--full-scan' in sys.argv or '-fs' in sys.argv else 0.25,
                    help='Delay between requests in seconds (default: 0.25 for custom/quick scan, 0 for full scan)')
parser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                    help='Enable progress output')
parser.add_argument('--display-closed', '-dc', dest='display_closed', action='store_true',
                    help='Display closed ports in the output and log file')
parser.add_argument('--display-timeout', '-dt', dest='display_timeout', action='store_true',
                    help='Display timed out ports in the output and log file')

group_file.add_argument('--logfile', '-l', dest='logfile', type=str, default=None,
                    help='Filename to save the scan results (optional e.g., scan.log')
group_file.add_argument('--csv', '-c', dest='csv', type=str, default=None,
                    help='Filename to save the scan results in CSV format (optional e.g., scan.csv)')
args = parser.parse_args()

def logAttempt(results, log):
    logPath = '.\\logs\\'
    with open(logPath + log, 'a') as file:
        file.write(f"{'IP ADDRESS':<20} {'PORT':<8} {'STATUS':<10} {'SERVICE/BANNER':<10}\n")
        for ip, entries in results.items():
            for ele in entries:
                # ele is expected to be (port, status) or (port, status, banner)
                port = ele[0]
                status = ele[1]
                banner = ele[2] if len(ele) > 2 else ''
                if status == 'closed' and args.display_closed:
                    file.write(f"{ip:<20} {port :<8} " + f"{status.upper():<10} \n")
                elif status == 'timeout' and args.display_timeout:
                    file.write(f"{ip:<20} {port :<8} " + f"{status.upper():<10} \n")
                elif status != 'closed' and status != 'timeout':
                    file.write(f"{ip:<20} {port :<8} " + f"{status.upper():<10} " + f"{banner if banner else common_ports.get(port, ''):<10}\n")

def log_csv(results, log):

    logPath = '.\\logs\\'
    with open(logPath + log, 'a', newline='') as file:
        for ip, entries in results.items():
            for ele in entries:
                port = ele[0]
                status = ele[1]
                banner = ele[2] if len(ele) > 2 else ''
                service = common_ports.get(port, '')
                safe_service = (service or '').replace(',', ';')
                safe_banner = (banner or '').replace(',', ';')

                if status == 'closed' and args.display_closed:
                    file.write(f"{time.ctime()},{ip},{port},CLOSED,,\n")
                elif status == 'timeout' and args.display_timeout:
                    file.write(f"{time.ctime()},{ip},{port},TIMEOUT,,\n")
                elif status != 'closed' and status != 'timeout':
                    file.write(f"{time.ctime()},{ip},{port},OPEN,{safe_service},{safe_banner}\n")
def ip_range(ele):
    octets = ele.split('.')
    split_octets = list(octet.split('-') for octet in octets)
    ranges = [range(int(i[0]), int(i[1]) + 1) if len(i) == 2 else i for i in split_octets]
    
    for addr in itertools.product(*ranges):
        ip = '.'.join(map(str, addr))
        yield ip


def ping_sweep(ips):
    ips_list = list(ip_range(ips))
    num_ip = len(ips_list)
    print(Fore.GREEN + f"\nSearching for active hosts in range {ips}...\n")
    progrss = tqdm(total=num_ip, desc="Pinging...", leave=False)

    for ip in ips_list:
       if os.system(f"ping -n 1 {ip} | find \"TTL\" > NUL") == 0:
            ip_active.append(ip)
       progrss.update(1)

    progrss.close()            
    print(f"{len(ip_active)} hosts are active.\n")


def enqueue_ports(start_port, end_port):
    for ip in ip_active:
        for port in range(start_port, end_port + 1):
            que.put((ip, port))


def regex_range(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?$", re.IGNORECASE)
    return pattern.match(input_text)


def regex_ip(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", re.IGNORECASE)
    return pattern.match(input_text)


def printout(i, start, end):
    sort_i = dict(sorted(i.items()))
    for ip, entries in sort_i.items():
        print(Fore.MAGENTA + f"\nScan results for {ip}:\n")
        print(f"{'PORT' :<8} {'STATUS':<10} {'SERVICE' :<10} {'BANNER'}")
        print(f"{'-'*8} {'-'*10} {'-'*10} {'-'*15}")
        for ele in entries:
            port = ele[0]
            status = ele[1]
            banner = ele[2] if len(ele) > 2 else ''
            if status == 'timeout' and args.display_timeout:
                print(Fore.WHITE + f"{port :<8}", Fore.YELLOW + f" {status.upper():<10}")
            elif status == 'closed' and args.display_closed:
                print(Fore.WHITE + f"{port :<8}", Fore.RED + f" {status.upper():<10}")
            elif status != 'closed' and status != 'timeout':
                print(Fore.WHITE + f"{port :<8}", Fore.GREEN + f" {status.upper():<10}" + Fore.WHITE + f" {common_ports.get(port, '') :<10} {banner}")
        print(f"Scan completed for {ip}.\n")
    total = end - start
    print(f"Time taken: {total:.2f} seconds\n")



def worker(delay, progress_bar, verbose, locking):

    while not que.empty():
        status = ''
        banner = ''
        try:
            ip, port = que.get()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                status = 'open'
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                except:
                    banner = ''
                with locking:
                    if ip not in results:
                        results[ip] = set()
                    results[ip].add((port, status, banner))
                if verbose:
                    with locking:
                        print(Fore.WHITE + f"{port :<8}" + Fore.GREEN + "OPEN" + Fore.WHITE + f" {banner if banner else common_ports.get(port, '')}")
            else:
                status = 'closed'
                with locking:
                    if ip not in results:
                        results[ip] = set()
                    results[ip].add((port, status))
                if verbose:
                    with locking:
                        print(Fore.WHITE + f"{port :<8}" + Fore.RED + "CLOSED")

        except socket.timeout:
            status = 'timeout'
            if verbose:
                with locking:
                    print(Fore.WHITE + f"{port :<8}" + Fore.YELLOW + "TIMED OUT")
            with locking:
                if ip not in results:
                    results[ip] = set()
                results[ip].add((port, status))

        except Exception as e:
            print(f'Error scanning port {port}: {e}')
        finally:
            sock.close()
            progress_bar.update(1)
            que.task_done()
            time.sleep(delay)


def main():

    if args.ipr:
        regex_range(args.ipr)
        if not regex_range(args.ipr):
            print(Fore.RED + "Invalid IP range format. Use format like 192-193.168.1-2.1-255")
            sys.exit(1)
    else:
        regex_ip(args.ip)
        if not regex_ip(args.ip):
            print(Fore.RED + "Invalid IP format. Use format like 192.168.1.1")
            sys.exit(1)

    start_port = 0
    if args.quick_scan:
        end_port = 1024
    elif args.full_scan:
        end_port = 65535
    else:
        port_range = args.custom_scan.split('-')
        start_port = int(port_range[0])
        end_port = int(port_range[1])

    if args.ipr:
        ping_sweep(args.ipr)
    else:
        ping_sweep(args.ip)

    if args.port_list:
        port_list = [int(port.strip()) for port in args.port_list.split(',')]
        for ip in ip_active:
            for port in port_list:
                que.put((ip, port))
    else:
        enqueue_ports(start_port, end_port)

    print(Fore.GREEN + f"\nStarting scan active hosts from port {start_port} to {end_port}...\n")
    
    total_scans = len(ip_active) * (end_port - start_port + 1)
    progress_bar = tqdm(total=total_scans, desc="Scanning", unit="port")
    start_time = time.time()
    threads = []
    for t in range(args.threads):
        thread = threading.Thread(target=worker, args=(args.delay, progress_bar, args.verbose, locking))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    progress_bar.close()
    end_time = time.time()

    if args.logfile:
        logAttempt(results, args.logfile)
    elif args.csv:
        log_csv(results, args.csv)

    printout(results, start_time, end_time)

if __name__ == "__main__":
    main()

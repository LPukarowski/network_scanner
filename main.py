import argparse
import socket
import threading
import time
import sys
from colorama import init, Fore
from tqdm import tqdm
from pathlib import Path
import output
import validate
import sweep
import globals


locking = threading.Lock()

init(autoreset=True)


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

group_file.add_argument('--log', '-l', dest='logFile', type=str, default=None,
                    help='Filename to save the scan results (optional e.g., scan.log')
group_file.add_argument('--csv', '-c', dest='csvFile', type=str, default=None,
                    help='Filename to save the scan results in CSV format (optional e.g., scan.csv)')
args = parser.parse_args()






def worker(*, delay, progress_bar, verbose, locking):

    while not globals.que.empty():
        status = ''
        banner = ''
        try:
            ip, port = globals.que.get()
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
                    if ip not in globals.results:
                        globals.results[ip] = set()
                    globals.results[ip].add((port, status, banner))
                if verbose:
                    with locking:
                        print(Fore.WHITE + f"{port :<8}" + Fore.GREEN + "OPEN" + Fore.WHITE + f" {banner if banner else globals.possible_service.get(port, '')}")
            else:
                status = 'closed'
                with locking:
                    if ip not in globals.results:
                        globals.results[ip] = set()
                    globals.results[ip].add((port, status))
                if verbose:
                    with locking:
                        print(Fore.WHITE + f"{port :<8}" + Fore.RED + "CLOSED")

        except socket.timeout:
            status = 'timeout'
            if verbose:
                with locking:
                    print(Fore.WHITE + f"{port :<8}" + Fore.YELLOW + "TIMED OUT")
            with locking:
                if ip not in globals.results:
                    globals.results[ip] = set()
                globals.results[ip].add((port, status))

        except Exception as e:
            print(f'Error scanning port {port}: {e}')
        finally:
            sock.close()
            progress_bar.update(1)
            globals.que.task_done()
            time.sleep(delay)


def main():

    if args.ipr:
        if not validate.regex_range(args.ipr):
            print(Fore.RED + "Invalid IP range format. Use format like 192-193.168.1-2.1-255", file=sys.stderr)
            sys.exit(1)
    else:
        if not validate.regex_ip(args.ip):
            print(Fore.RED + "Invalid IP format. Use format like 192.168.1.1", file=sys.stderr)
            sys.exit(1)

    if args.logFile:
        if not validate.sanitize_file(args.logFile):
            ext = Path(args.logFile).suffix.lower()
            print(Fore.RED + f"Invalid file type '{ext}'. Only .log and .txt accepted as file type.", file=sys.stderr)
            sys.exit(1)

    if args.csvFile:
        if not validate.sanitize_csv(args.csvFile):
            ext = Path(args.csvFile).suffix.lower()
            print(Fore.RED + f"Invalid file type '{ext}'. File type must be .csv.", file=sys.stderr)
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
        sweep.ping_sweep(args.ipr)
    else:
        sweep.ping_sweep(args.ip)

    if args.port_list:
        port_list = [int(port.strip()) for port in args.port_list.split(',')]
        for ip in globals.ip_active:
            for port in port_list:
                globals.que.put((ip, port))
    else:
        sweep.enqueue_ports(start_port, end_port)

    print(Fore.GREEN + f"\nStarting scan active hosts from port {start_port} to {end_port}...\n")
    
    total_scans = len(globals.ip_active) * (end_port - start_port + 1)
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

    if args.logFile:
        output.logAttempt(log=args.logFile, display_closed=args.display_closed, display_timeout=args.display_timeout)
    elif args.csvFile:
        output.log_csv(log=args.csvFile, display_closed=args.display_closed, display_timeout=args.display_timeout)

    output.printout(start=start_time, end=end_time, display_closed=args.display_closed, display_timeout=args.display_timeout)

if __name__ == "__main__":
    main()

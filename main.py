import argparse
import socket
import threading
import time
from queue import Queue
import sys
from scapy.all import *
import itertools
from colorama import init, Fore
import re

que = Queue()

init(autoreset=True)
c_error = Fore.RED
c_info = Fore.MAGENTA
c_other = Fore.GREEN

common_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 
                143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 
                3389: 'RDP'}

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
parser.add_argument('--delay', '-d', dest='delay', type=int,
                    default=0 if '--full-scan' in sys.argv or '-fs' in sys.argv else 1)
parser.add_argument('--verbose', '-v', dest='verbose', action='store_true')
parser.add_argument('--logfile', '-l', dest='logfile', type=str)
args = parser.parse_args()

def use_regex(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?$", re.IGNORECASE)
    return pattern.match(input_text)


def known_banner():
    print("====================================== \n")
    print(Fore.MAGENTA, "This scan includes known common ports \n")
    print("====================================== \n")

def ip_range(ele):
    octets = ele.split('.')
    split_octets = list(octet.split('-') for octet in octets)
    ranges = [range(int(i[0]), int(i[1]) + 1) if len(i) == 2 else i for i in split_octets]
    
    for addr in itertools.product(*ranges):
        ip = '.'.join(map(str, addr))
        
        yield ip


def worker(delay):

    while not que.empty():
        
        try:
            ip, port = que.get() 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(Fore.MAGENTA, f'{port}   open\n')
        except ConnectionRefusedError:
            print(Fore.MAGENTA, f'{port}   closed\n')

        except socket.timeout:
            if args.verbose:
                print(Fore.MAGENTA, f'{port}   timed out\n')      

        except Exception as e:
            print(f'Error scanning port {port}: {e}')
        finally:
            sock.close()
            que.task_done()
            time.sleep(delay)


def main():

    ip_r = []

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
        input("\nPress Enter to continue...")
    elif args.full_scan:
        start_port = 1
        end_port = 65535
    else:
        start_port = int(input("\nEnter start port: "))
        end_port = int(input("\nEnter end port: \n"))
        if any(port in common_ports for port in range(start_port, end_port + 1)):
            known_banner()
        
    for ip in ip_range(input_ip):
        for port in range(start_port, end_port + 1):
            que.put((ip, port))
            
    threads = []
    for t in range(args.threads):
        thread = threading.Thread(target=worker, args=(args.delay))
        threads.append(thread)
        thread.start()
        thread.join()

if __name__ == "__main__":
    main()

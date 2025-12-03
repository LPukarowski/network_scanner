import argparse
import socket
import threading
import time
from queue import Queue
import sys

q = Queue()
known = 0
common_ports = {22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 
                143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 
                3389: 'RDP'}

def known_banner():
    print("====================================== \n")
    print("This scan includes known common ports \n")
    print("====================================== \n")


def worker():

    while not q.empty():
        
        try:
            port = q.get()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f'Port {port} is open')
        except ConnectionRefusedError:
            print(f'Port {port} is closed')

        except socket.timeout:
            print(f'Port {port} timed out')      

        except Exception as e:
            print(f'Error scanning port {port}: {e}')
        finally:
            sock.close()
            q.task_done()


def main():

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group_ip = parser.add_mutually_exclusive_group(required=True)
    group_port = parser.add_mutually_exclusive_group()
    
    group.add_argument('--quick-scan', '-qs', dest='quick_scan', action='store_true')
    group.add_argument('--full-scan', '-fs', dest='full_scan', action='store_true')

    group_ip.add_argument('--range', '-r', dest='range', action='store_true')
    group_ip.add_argument('--single-ip', '-s', dest='single_ip', action='store_true')

    group_port.add_argument('--default-ports', '-dp', dest='default_ports', action='store_true')
    group_port.add_argument('--all-ports', '-ap', dest='all_ports', action='store_true')

    parser.add_argument('--threads', '-t', dest='threads', type=int, 
                        default=10 if '--quick-scan' in sys.argv or '-qs' in sys.argv else 30)
    parser.add_argument('--delay', '-d', dest='delay', type=int,
                        default=1 if '--quick-scan' in sys.argv or '-qs' in sys.argv else 0)
    parser.add_argument('--verbose', '-v', dest='verbose', action='store_true')
    args = parser.parse_args()

    print("threads:", args.threads)
    print("delay:", args.delay)

    if args.range:
        ip_start_range = input("Enter starting IP: ")
        ip_end_range = input("Enter ending IP: ")
    else:
        target_ip = input("Enter target IP: ")

    if not args.default_ports and not args.all_ports:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
    elif args.default_ports:
        start_port = 1
        end_port = 1024
    else:
        start_port = 1
        end_port = 65535

    
    
    for port in range(start_port, end_port + 1):
        q.put(port)
        if known == 0:
            if port in common_ports:
                known += 1

    threads = []
    for t in range(args.threads):
        thread = threading.Thread(target=worker, args=(args.url, args.delay))
        threads.append(thread)
        thread.start()
        thread.join()

if __name__ == "__main__":
    main()

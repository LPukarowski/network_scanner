import argparse
from html import parser
import socket
import threading
import time
from queue import Queue

q = Queue()
known = 0
common_ports = {22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 
                143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 
                3389: 'RDP'}
def known_banner():
    print("Known banner function")


def worker():

    while not q.empty():
        
        try:
            port = q.get()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f'Port {port} is open')
            
            
            
        except Exception as e:
            print('Error')


def main():

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('--quick-scan', '-qs', dest='quick_scan', action='store_true')
    group.add_argument('--full-scan', '-fs', dest='full_scan', action='store_true')
    parser.add_argument('--ip-range', '-ip', dest='ip_range', action='store_true')
    parser.add_argument('--threads', '-t', dest='threads', type=int, default=5)
    parser.add_argument('--delay', '-d', dest='delay', type=int, default=1)
    parser.add_argument('--verbose', '-v', dest='verbose', action='store_true')

    args = parser.parse_args()

    if args.ip_range:
        ip_start_range = input("Enter starting IP: ")
        ip_end_range = input("Enter ending IP: ")

    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    
    for port in range(start_port, end_port + 1):
        q.put(port)
        if known == 0:
            if port in common_ports:
                known += 1


if __name__ == "__main__":
    main()

import argparse

import socket
import threading
import time
from queue import Queue

q = Queue()
common_ports = {22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 
                143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 
                3389: 'RDP'}
def known_banner():
    print("Known banner function")


def worker(target_ip, stop_event):

    while not q.empty() and not stop_event.is_set():
        
        try:
            port = q.get()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f'Port {port} is open')
            
            
            
        except req.exceptions.RequestException as e:
            print('Error')


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('--wordlist', '-w', dest='wordlist', required=True)
    parser.add_argument('--username', '-u', dest='uname', required=True)
    parser.add_argument('--target-url', '-url', dest='url', default='http://127.0.0.1:5000/login')
    parser.add_argument('--threads', '-t', dest='threads', type=int, default=2)
    parser.add_argument('--delay', '-d', dest='delay', type=int, default=0.25)
    parser.add_argument('--stop-on-success', '-sS', dest='stopOnSuccess', action='store_true')
    parser.add_argument('--log', '-l', dest='log', required=True)
    parser.add_argument('--allow-remote', '-aR', dest='ar', action='store_true')

    args = parser.parse_args()

    for port in range(args.start_port, args.end_port + 1):
        q.put(port)
        if known == 0:
            if port in common_ports:
                known += 1


if __name__ == "__main__":
    main()

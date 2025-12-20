import itertools
import os
from colorama import Fore
from tqdm import tqdm
import globals


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
            globals.ip_active.append(ip)
       progrss.update(1)

    progrss.close()            
    print(f"{len(globals.ip_active)} hosts are active.\n")


def enqueue_ports(start_port, end_port):
    for ip in globals.ip_active:
        for port in range(start_port, end_port + 1):
            globals.que.put((ip, port))
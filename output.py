import globals
from time import time
from colorama import Fore



def printout(*, i, start, end, display_timeout=False, display_closed=False):
    sort_i = dict(sorted(i.items()))
    for ip, entries in sort_i.items():
        print(Fore.MAGENTA + f"\nScan results for {ip}:\n")
        print(f"{'PORT' :<8} {'STATUS':<10} {'SERVICE' :<10} {'BANNER'}")
        print(f"{'-'*8} {'-'*10} {'-'*10} {'-'*15}")
        for ele in entries:
            port = ele[0]
            status = ele[1]
            banner = ele[2] if len(ele) > 2 else ''
            if status == 'timeout' and display_timeout:
                print(Fore.WHITE + f"{port :<8}", Fore.YELLOW + f" {status.upper():<10}")
            elif status == 'closed' and display_closed:
                print(Fore.WHITE + f"{port :<8}", Fore.RED + f" {status.upper():<10}")
            elif status != 'closed' and status != 'timeout':
                print(Fore.WHITE + f"{port :<8}", Fore.GREEN + f" {status.upper():<10}" + Fore.WHITE + f" {globals.common_ports.get(port, '') :<10} {banner}")
        print(f"Scan completed for {ip}.\n")
    total = end - start
    print(f"Time taken: {total:.2f} seconds\n")

def logAttempt(*, results, log, display_timeout=False, display_closed=False):
    logPath = '.\\logs\\'
    with open(logPath + log, 'a') as file:
        file.write(f"{'IP ADDRESS':<20} {'PORT':<8} {'STATUS':<10} {'SERVICE/BANNER':<10}\n")
        for ip, entries in results.items():
            for ele in entries:
                # ele is expected to be (port, status) or (port, status, banner)
                port = ele[0]
                status = ele[1]
                banner = ele[2] if len(ele) > 2 else ''
                if status == 'closed' and display_closed:
                    file.write(f"{ip:<20} {port :<8} " + f"{status.upper():<10} \n")
                elif status == 'timeout' and display_timeout:
                    file.write(f"{ip:<20} {port :<8} " + f"{status.upper():<10} \n")
                elif status != 'closed' and status != 'timeout':
                    file.write(f"{ip:<20} {port :<8} " + f"{status.upper():<10} " + f"{banner if banner else globals.common_ports.get(port, ''):<10}\n")

def log_csv(*, results, log, display_timeout=False, display_closed=False):

    logPath = '.\\logs\\'
    with open(logPath + log, 'a', newline='') as file:
        for ip, entries in results.items():
            for ele in entries:
                port = ele[0]
                status = ele[1]
                banner = ele[2] if len(ele) > 2 else ''
                service = globals.common_ports.get(port, '')
                safe_service = (service or '').replace(',', ';')
                safe_banner = (banner or '').replace(',', ';')

                if status == 'closed' and display_closed:
                    file.write(f"{time.ctime()},{ip},{port},CLOSED,,\n")
                elif status == 'timeout' and display_timeout:
                    file.write(f"{time.ctime()},{ip},{port},TIMEOUT,,\n")
                elif status != 'closed' and status != 'timeout':
                    file.write(f"{time.ctime()},{ip},{port},OPEN,{safe_service},{safe_banner}\n")
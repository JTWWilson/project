import nmap
import sys
from socket import gethostbyaddr, herror
from utils import is_local_ip_address

print(sys.argv)

def get_targets() -> list:
    """Gets a list of targets for the probe from sys.argv"""
    pass

def probe_ip_address(ip_address: str):
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments="-O")

    try:
        if 'osmatch' in scanner[ip_address]:
            if len(scanner[ip_address]['osmatch']) > 0:
                return [scanner[ip_address]['osmatch'][0]['name'], scanner[ip_address]['osmatch'][0]['accuracy']]           

        return ["No match for OS found", -1]
    except KeyError as e:
        print(e)
        print(scanner)
        return ["Scan incomplete", -1]

targets = []
hosts = []
for target in targets:
    try:
        hosts.append(gethostbyaddr(target))
    except herror:
        hosts.append('No host found')
print(hosts)

print('Local devices:')
for index, target in enumerate(targets):
    if is_local_ip_address(target):
        print('Probing: {} : {}'.format(hosts[index], target))
        guess = probe_ip_address(target)
        print("{} is running {} with {} accuracy".format(target, guess[0], guess[1]))

print('External devices:')
for index, target in enumerate(targets):
    if not is_local_ip_address(target):
        print('Probing: {} : {}'.format(hosts[index], target))
        guess = probe_ip_address(target)
        print("{} is running {} with {} accuracy".format(target, guess[0], guess[1]))
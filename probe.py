import nmap
import sys

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

print('Local devices:')
for target in targets:
    if target.startswith("192.168"):
        print('Probing: {}'.format(target))
        guess = probe_ip_address(target)
        print("{} is running {} with {} accuracy".format(target, guess[0], guess[1]))

print('External devices:')
for target in targets:
    if not target.startswith("192.168"):
        print('Probing: {}'.format(target))
        guess = probe_ip_address(target)
        print("{} is running {} with {} accuracy".format(target, guess[0], guess[1]))
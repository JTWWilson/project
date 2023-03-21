import nmap
import sys
from socket import gethostbyaddr, herror
from utils import is_local_ip_address
import sqlite3
from device import Device
from scapy.layers.l2 import getmacbyip
import socket
import ssl
from cryptography import x509
from utils import is_reserved_mac_address,get_manufacturer_from_mac
from device_db_manager import add_device_to_database

DEFAULT_DB_NAME = 'devices.db'

def get_targets() -> list:
    """Gets a list of targets for the probe from sys.argv"""
    pass


def probe_device_name(mac: str):
    router = 0
    if '@' in mac:
        ip, mac = mac.split('@')

    if ip is not None:
        try:
            # First try getting the device name
            name = socket.gethostbyaddr(ip)
            add_device_to_database(connection, ip + '@' + mac, name=name[0], is_router=router)
            return name[0]
        except socket.herror:
            pass
        try:
            cert = ssl.get_server_certificate((ip, 443))
            cert_decoded = x509.load_pem_x509_certificate(str.encode(cert)) 
            return cert_decoded.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except OSError:
            pass
    print(ip)
    # Check if the MAC address is reserved for something like multicast
    reserved, reason = is_reserved_mac_address(mac)
    if reserved:
        add_device_to_database(connection, mac, name=reason, is_router=router)
        return reason
    # If that fails, try getting the manufacturer from the MAC address
    manufacturer = get_manufacturer_from_mac(mac)
    if manufacturer != "":
        add_device_to_database(connection, mac, name=manufacturer, is_router=router)
        return manufacturer
    else:
        add_device_to_database(connection, mac, is_router=router)
        return mac


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


def probe_device(device: Device):
    for ip in device.ip_addresses:
        probe_ip_address(ip)

targets = []

def probe_list_of_targets(targets, device_db=DEFAULT_DB_NAME):
    connection = sqlite3.connect(device_db)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS DEVICES (
            mac TEXT NOT NULL PRIMARY KEY,
            name TEXT,
            os TEXT,
            certainty INTEGER
        );
    """)

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

if __name__ == '__main__':
    connection = sqlite3.connect(DEFAULT_DB_NAME)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS DEVICES (
            mac TEXT NOT NULL PRIMARY KEY,
            name TEXT,
            os TEXT,
            certainty INTEGER
        );
    """)
import re
import socket
import sqlite3
from utils import get_manufacturer_from_mac, is_reserved_mac_address
import ssl
from cryptography import x509

DEFAULT_DB_NAME = 'devices.db'

def ensure_device_table_exists(connection: sqlite3.Connection) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS DEVICES (
            mac TEXT NOT NULL PRIMARY KEY,
            name TEXT,
            os TEXT,
            certainty INTEGER
        );
    """)


def get_device_name(mac: str, ip: str =None, device_db=DEFAULT_DB_NAME) -> str:
    """Returns a human readable name for a device from a mac address"""
    with sqlite3.connect(device_db) as connection:
        ensure_device_table_exists(connection)
        # Look for the MAC address in the device database
        name = connection.execute("SELECT name FROM DEVICES WHERE mac = '{}';".format(mac)).fetchall()
        # If it's in the database, return its name, else try to work out its name 
        if name != []:
            return name[0][0]

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

def add_device_to_database( mac: str, device_db=DEFAULT_DB_NAME, name='', os_guess=['No Guess', -1], is_router=0):
    with sqlite3.connect(device_db) as connection:
        ensure_device_table_exists(connection)
        existing_record = connection.execute("SELECT * FROM DEVICES WHERE mac = '{}';".format(mac))
        if existing_record.fetchall() == []:
            connection.execute("INSERT OR REPLACE INTO DEVICES (mac, name, os, certainty, is_router) VALUES ('{}','{}','{}','{}', {});".format(mac, name, os_guess[0], os_guess[1], is_router))
        else:
            update = ""
            if name != "":
                update += "name = '{}',".format(name)
            if os_guess != ['No Guess', -1]:
                update += "os = '{}', certainty = '{}'".format(os_guess[0], os_guess[1])
            #print("UPDATE DEVICES SET " + update.rstrip(',') + " WHERE mac = '{}';".format(mac))
            connection.execute("UPDATE DEVICES SET " + update.rstrip(',') + " WHERE mac = '{}';".format(mac))


def is_in_router_list(mac: str, device_db=DEFAULT_DB_NAME) -> bool:
    return mac in get_router_list(device_db=device_db)


def get_router_list(device_db=DEFAULT_DB_NAME) -> list[str]:
    with sqlite3.connect(device_db) as connection:
        ensure_device_table_exists(connection)
        response = connection.execute("SELECT mac FROM DEVICES WHERE is_router = 1;").fetchall()
        return [r[0] for r in response]


if __name__ == "__main__":
    get_router_list()
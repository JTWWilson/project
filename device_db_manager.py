import socket
import sqlite3
from utils import get_manufacturer_from_mac, is_reserved_mac_address

DEFAULT_DB_NAME = 'devices.db'

def ensure_table_exists(connection: sqlite3.Connection) -> None:
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
        ensure_table_exists(connection)
        # Look for the MAC address in the device database
        name = connection.execute("SELECT name FROM DEVICES WHERE mac = '{}';".format(mac)).fetchall()
        # If it's in the database, return its name, else try to work out its name 
        if name != []:
            return name[0][0]

        if '@' in mac:
            ip, mac = mac.split('@')

        if ip is not None:
            try:
                # First try getting the device name
                name = socket.gethostbyaddr(ip)
                add_device_to_database(connection, mac + '@' + ip, name[0])
                return name[0]
            except socket.herror:
                pass
        # Check if the MAC address is reserved for something like multicast
        reserved, reason = is_reserved_mac_address(mac)
        if reserved:
            add_device_to_database(connection, mac, reason)
            return reason
        # If that fails, try getting the manufacturer from the MAC address
        manufacturer = get_manufacturer_from_mac(mac)
        if manufacturer != "":
            add_device_to_database(connection, mac, manufacturer)
            return manufacturer
        else:
            add_device_to_database(connection, mac)
            return mac

def add_device_to_database(connection: sqlite3.Connection, mac: str, name='', os_guess=['No Guess', -1]):
    with connection:
        ensure_table_exists(connection)
        existing_record = connection.execute("SELECT * FROM DEVICES WHERE mac = '{}';".format(mac))
        if existing_record.fetchall() == []:
            connection.execute("INSERT OR REPLACE INTO DEVICES (mac, name, os, certainty) VALUES ('{}','{}','{}','{}');".format(mac, name, os_guess[0], os_guess[1]))
        else:
            update = ""
            if name != "":
                update += "name = '{}',".format(name)
            if os_guess != ['No Guess', -1]:
                update += "os = '{}', certainty = '{}'".format(os_guess[0], os_guess[1])
            #print("UPDATE DEVICES SET " + update.rstrip(',') + " WHERE mac = '{}';".format(mac))
            connection.execute("UPDATE DEVICES SET " + update.rstrip(',') + " WHERE mac = '{}';".format(mac))
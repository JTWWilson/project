import sqlite3

DEFAULT_DB_NAME = 'devices.db'

def ensure_device_table_exists(connection: sqlite3.Connection) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS DEVICES (
            mac TEXT NOT NULL PRIMARY KEY,
            name TEXT,
            os TEXT,
            certainty INTEGER,
            is_router INTEGER
        );
    """)


def get_device_name(mac: str, device_db=DEFAULT_DB_NAME) -> str:
    """Returns a human readable name for a device from the database by mac address"""
    with sqlite3.connect(device_db) as connection:
        ensure_device_table_exists(connection)
        # Look for the MAC address in the device database
        name = connection.execute("SELECT name FROM DEVICES WHERE mac = '{}';".format(mac)).fetchall()
        # If it's in the database, return its name, else return its MAC
        if name != []:
            return name[0][0]
        else:
            return mac


def get_os_guess(mac: str, device_db=DEFAULT_DB_NAME) -> str:
    with sqlite3.connect(device_db) as connection:
        ensure_device_table_exists(connection)
        # Look for the MAC address in the device database
        os_guess = connection.execute("SELECT os, certainty FROM DEVICES WHERE mac = '{}';".format(mac)).fetchall()
        # If it's in the database, return its name, else return its MAC
        if os_guess != []:
            return os_guess[0]
        

def add_device_to_database(mac: str, device_db=DEFAULT_DB_NAME, name='', os_guess=['No Guess', -1], is_router=0):
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
                update += "os = '{}', certainty = '{}',".format(os_guess[0], os_guess[1])
            update += "is_router = '{}'".format(is_router)
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
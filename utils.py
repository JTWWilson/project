import requests
from dotenv import dotenv_values
from json import loads

def is_local_ip_address(ip_address: str) -> bool:
    """Returns True if the ip address is in the local address range."""
    if ip_address.startswith('10.') or ip_address.startswith('192.168'):
        return True
    if ip_address.startswith('172.') and 16 <= int(ip_address.split('.')[1]) < 32:
        return True
    return False


def is_reserved_mac_address(mac: str) -> "tuple[bool, str]":
    """
    Returns boolean of whether the MAC address is reserved.
    Sources of truth: https://en.wikipedia.org/wiki/Multicast_address; https://www.rfc-editor.org/rfc/rfc5342
    TODO: Make this slightly more detailed and more true.
    """
    mac = mac.upper()
    if mac == "FF:FF:FF:FF:FF:FF":
        return True, "Ethernet Broadcast"
    if mac.startswith("01:80:C2"):
        return True, "Multicast"
    if mac.startswith("01:1B:19"):
        return True, "Multicast"
    if mac.startswith("01:00:5E"):
        return True, "IPv4 Multicast"
    if mac.startswith("33:33"):
        return True, "IPv6 Multicast"
    if mac.startswith("01:0C:CD"):
        return True, "Multicast"
    if mac.startswith("01:00:0C"):
        return True, "Cisco Multicast"
    if mac.startswith("CF"):
        return True, "Reserved for PPP"
    return False, "Unknown"


def get_manufacturer_from_mac(mac: str) -> str:
    config = dotenv_values(".env")
    response = requests.get("https://api.maclookup.app/v2/macs/{}?apiKey={}".format(mac, config['maclookup_api_key']))
    if response.status_code == 200:
        return loads(response.text)["company"]
    else:
        return ""


if __name__ == "__main__":
    print(get_manufacturer_from_mac('00:00:00:00:00:00'))
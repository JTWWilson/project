import requests
from dotenv import dotenv_values
from json import loads

def is_local_ip_address(ip_address: str) -> bool:
    """Returns True if the ip address is in the local address range."""
    if ip_address.startswith('10.') or ip_address.startswith('192.168'):
        return True
    if 16 <= int(ip_address.split('.')[1]) < 32:
        return True
    return False


def get_manufacturer_from_mac(mac: str) -> str:
    config = dotenv_values(".env")
    response = requests.get("https://api.maclookup.app/v2/macs/{}?apiKey={}".format(mac, config['maclookup_api_key']))
    if response.status_code == 200:
        return loads(response.text)["company"]
    else:
        return ""


if __name__ == "__main__":
    print(get_manufacturer_from_mac('00:00:00:00:00:00'))
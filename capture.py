import pyshark
from datetime import datetime
from scapy.all import sr1, Ether, ARP
import threading
import re
from ping3 import ping
from subprocess import Popen, PIPE
from device_db_manager import add_device_to_database, get_device_name

def capture(output_file=None):
    # Default name for file is the date and time of its capture
    if output_file is None:
        now = datetime.now()
        output_file = "{}-{}-{}_{}-{}-{}.pcap".format(now.year, now.month, now.day, now.hour, now.minute, now.second)
    cap = pyshark.LiveCapture(output_file=output_file, interface="WiFi")
    # threading.Thread(target=walk_local_ipv4, daemon=True).start()
    threading.Thread(target=cap.sniff, kwargs={'timeout': 60}).start()
    ping("192.168.255.255")
    ping("10.255.255.255")


def send_arp(ip: str):
    print(sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=3))


def get_first_tracert_hop(end: str="8.8.8.8") -> str:
    p = Popen(['tracert', '-h', '1', end], stdout=PIPE)
    # Assuming that the router is one hop away
    while True:
        line = p.stdout.readline()
        if not line:
            break
        ips_ish = re.findall("\d+\.\d+\.\d+\.\d+",str(line))
        if ips_ish and end not in ips_ish:
            return ips_ish[0]
    raise NotImplementedError()

def get_first_arp_entry_by_ip(ip) -> str:
    p = Popen(['arp', '-a', ip], stdout=PIPE)
    while True:
        line = p.stdout.readline()
        if not line:
            break
        mac_ish = re.findall("..-..-..-..-..-..",str(line))
        if mac_ish:
            return ':'.join(mac_ish[0].split('-'))


def get_router_addresses(host: str="8.8.8.8") -> "tuple[str, str]":
    """Return the MAC and IP addresses of the first hop away from the device towards a server, default being Google's 8.8.8.8
    I am assuming this hop takes you to the router."""
    router_ip = get_first_tracert_hop(end=host)
    router_mac = get_first_arp_entry_by_ip(router_ip)

    add_device_to_database(router_mac, name=get_device_name(router_mac, router_ip), is_router=1)


def walk_local_ipv4():
    ip_base = "192.168"
    for a in range(256):
        for b in range(256):
            send_arp("{}.{}.{}".format(ip_base,a,b))


if __name__ == "__main__":
    capture()

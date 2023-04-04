import pyshark
from datetime import datetime
from scapy.all import sr1, Ether, ARP
import threading
import re
from ping3 import ping
from subprocess import Popen, PIPE
from device_db_manager import add_device_to_database, get_device_name
from analysis import Network
import probe
from device import Device
from utils import is_local_ip_address
import argparse


def capture(time: int =60, output_file=None, capture_interface: str ="WiFI") -> pyshark.capture.capture.Capture:
    # Default name for file is the date and time of its capture
    if output_file is None:
        now = datetime.now()
        output_file = "{}-{}-{}_{}-{}-{}.pcap".format(now.year, now.month, now.day, now.hour, now.minute, now.second)
    cap = pyshark.LiveCapture(output_file=output_file, interface=capture_interface)
    # threading.Thread(target=walk_local_ipv4, daemon=True).start()
    t = threading.Thread(target=cap.sniff, kwargs={'timeout': time})
    threading.Thread(target=count_up_to, args={time}).start()
    t.start()
    ping("192.168.255.255")
    ping("10.255.255.255")
    t.join()
    return output_file


def count_up_to(n):
    from time import sleep
    for i in range(1, n):
        sleep(1)
        print("Listening for {} seconds.".format(i), end="\r")
    print("Listening for {} seconds.".format(n))
    

def send_arp(ip: str):
    print(sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=3))


def get_first_tracert_hop(end: str="8.8.8.8") -> str:
    p = Popen(['tracert', '-h', '1', end], stdout=PIPE)
    
    last_hop = ""
    while True:
        line = p.stdout.readline()
        if not line:
            break
        ips_ish = re.findall("\d+\.\d+\.\d+\.\d+",str(line))
        if not is_local_ip_address(ips_ish[0]) and end not in ips_ish:
            return last_hop
        last_hop = ips_ish
    raise NotImplementedError("Couldn't route to {}".format(end))

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
    return router_mac, router_ip


def walk_local_ipv4():
    ip_base = "192.168"
    for a in range(256):
        for b in range(256):
            send_arp("{}.{}.{}".format(ip_base,a,b))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Captures traffic on a network interface for a given amount of time and then records all devices seen along with guesses for their names and operating systems in a database.")
    parser.add_argument("--interface", "-i", default="WiFi", type=str, nargs='?', help='network interface to use (default: "WiFi")')
    parser.add_argument("--time", "-t", default=60, type=int, nargs='?', help='time to spend listening in seconds (default: 60)')
    parser.add_argument("--database", "--db", "-d", default="devices.db", type=str, nargs='?', help='database to store devices in (default: "devices.db")')
    args = parser.parse_args()
    output_file_name = capture(time=args.time, capture_interface=args.interface)
    print("Pcap exported to {}".format(output_file_name))
    devices = Network.get_devices_from_pcap(pyshark.FileCapture(output_file_name))
    router_mac, router_ip = get_router_addresses()
    print("Router identified with IP: {} and MAC {}".format(router_ip, router_mac))
    add_device_to_database(router_mac, 
            device_db=args.database,
            name=probe.probe_device_name(router_mac, router_ip), 
            os_guess=probe.probe_ip_address(router_ip), 
            is_router=1)
    device : Device
    for device in devices:
        add_device_to_database(device.MAC_ADDRESS, 
            device_db=args.database,
            name=probe.probe_device_name(device.MAC_ADDRESS, device.ip_addresses[0]), 
            os_guess=probe.probe_ip_address(device.ip_addresses[0]), 
            is_router=int(device.MAC_ADDRESS == router_mac))

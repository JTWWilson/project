import pyshark
from datetime import datetime
from scapy.all import sr1, Ether, ARP
import threading
from ping3 import ping

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



def walk_local_ipv4():
    ip_base = "192.168"
    for a in range(256):
        for b in range(256):
            send_arp("{}.{}.{}".format(ip_base,a,b))


if __name__ == "__main__":
    capture()

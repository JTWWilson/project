import pyshark
import typing
from typing_extensions import Literal
import mysql.connector
from dotenv import dotenv_values
import json

config = dotenv_values(".env")
"""
db = mysql.connector.connect(
  host="fyp-db.cytclda6g1lu.eu-west-2.rds.amazonaws.com",
  user=config['db_username'],
  password=config['db_password']
)

cursor = db.cursor()
cursor.execute("SHOW DATABASES")
print(type(cursor.fetchall()))
"""
pcap = pyshark.FileCapture('firstRead.pcap')


class Device:
    def __init__(self, mac_addr) -> None:
        self.MAC_ADDRESS = mac_addr
        self.ip_addresses = []
        self.devices_sent_to = []
        self.devices_received_from = []


class DeviceEncoder(json.JSONEncoder):
        def default(self, o):
            return o.__dict__


class Network:
    def __init__(self, devices=()) -> None:
        self.devices = devices

    @staticmethod
    def get_devices_from_pcap(pcap: pyshark.FileCapture):
        """Turns a pcap into a list of Devices"""
        iterable_pcap = iter(pcap)
        device_list = []

        while True:
            try:
                packet: pyshark.packet.packet.Packet = next(iterable_pcap) 
            except StopIteration:
                break
            if has_given_layer(packet, "ETH"):
                src_mac = packet.layers[0].src
                dst_mac = packet.layers[0].dst
                # If source device is new, create Device object and add it to ret
                if src_mac not in [d.MAC_ADDRESS for d in device_list]:
                    new_device = Device(src_mac)
                    if has_given_layer(packet, "IP"):
                        new_device.ip_addresses.append(packet.layers[1].src)
                    # If destination device is also new, create Device object and add it to ret
                    if dst_mac not in [d.MAC_ADDRESS for d in device_list]:                   
                        other_new_device = Device(dst_mac)
                        if has_given_layer(packet, "IP"):
                            other_new_device.ip_addresses.append(packet.layers[1].dst)
                        new_device.devices_sent_to.append(other_new_device)
                        other_new_device.devices_sent_to.append(new_device)
                    device_list.append(new_device)

        return device_list


def has_given_layer(
    packet: pyshark.packet.packet.Packet, 
    layer: Literal["ETH", "IP"] = "ETH") -> bool:
    try:
        packet[layer]
        return True
    except KeyError:
        return False


def get_all_addresses(
    pcap: pyshark.FileCapture, 
    address_layer: Literal["ETH", "IP"] = "ETH"
) -> typing.Set[str]:
    iterable_pcap = iter(pcap)
    addresses = set()
    LAYER_NAME_TO_INDEX = {"ETH" : 0, "IP" : 1}
    layer_index = LAYER_NAME_TO_INDEX[address_layer]

    i = 0
    while True: #i < 50:
        try:
            packet: pyshark.packet.packet.Packet = next(iterable_pcap) 
        except StopIteration:
            break
        if has_given_layer(packet, address_layer):
            src = packet.layers[layer_index].src
            dst = packet.layers[layer_index].dst
            for addr in (src, dst):
                if addr not in addresses:
                    addresses.add(addr)

        i += 1

    return addresses


def list_ips_by_mac(
    pcap: pyshark.FileCapture, 
) -> typing.List[Device]:
    iterable_pcap = iter(pcap)

    ret = []

    i = 0
    while True: #i < 50:
        try:
            packet: pyshark.packet.packet.Packet = next(iterable_pcap) 
        except StopIteration:
            break
        if has_given_layer(packet, "ETH"):
            # print(packet.layers)
            src_mac = packet.layers[0].src
            dst_mac = packet.layers[0].dst
            # If source device is new, create Device object and add it to ret
            if src_mac not in [d.MAC_ADDRESS for d in ret]:
                new_device = Device(src_mac)
                if has_given_layer(packet, "IP"):
                    new_device.ip_addresses.append(packet.layers[1].src)
                # If destination device is also new, create Device object and add it to ret
                if dst_mac not in [d.MAC_ADDRESS for d in ret]:                   
                    other_new_device = Device(dst_mac)
                    if has_given_layer(packet, "IP"):
                        other_new_device.ip_addresses.append(packet.layers[1].dst)
                    new_device.devices_sent_to.append(other_new_device)
                    other_new_device.devices_sent_to.append(new_device)
                ret.append(new_device)
        i += 1

    return ret


# # d = Device('ab:ac:ac')
# # d2 = Device('ac:ad:ad')
# # d.devices_received_from = [d2]
# # print(DeviceEncoder().encode(d))

#with open('export.json','w') as f:
#    f.write(json.dumps(list_ips_by_mac(pcap), indent=4, cls=DeviceEncoder))


#print(get_all_addresses(pcap, "ETH"))
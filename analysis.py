import pyshark
import typing
from typing_extensions import Literal
import mysql.connector
from dotenv import dotenv_values
import json
import networkx as nx
import matplotlib.pyplot as plt
from pickle import dump, load
from copy import deepcopy

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
        self.devices_sent_to = {}
        self.devices_received_from = {}

    def __repr__(self) -> str:
        return self.MAC_ADDRESS

    def __eq__(self, __o: object) -> bool:
        try:
            return self.MAC_ADDRESS == __o.MAC_ADDRESS
        except AttributeError:
            return False

    def __hash__(self) -> int:
        return hash(self.MAC_ADDRESS)


class DeviceEncoder(json.JSONEncoder):
        def default(self, o):
            return o.__dict__


class Network:
    def __init__(self, devices=()) -> None:
        self.devices = devices

    @staticmethod
    def add_to_device_dict(dct, device) -> dict:
        if device.MAC_ADDRESS in dct.keys():
            dct[device.MAC_ADDRESS] += 1
        else:
            dct[device.MAC_ADDRESS] = 1
        return dct

    @staticmethod
    def get_index_by_mac(devices: typing.List[Device], mac: str) -> int:
            for i, d in enumerate(devices):
                if d.MAC_ADDRESS == mac:
                    return i
            return False

    @staticmethod
    def get_device_by_mac(devices: typing.List[Device], mac: str):
            for d in devices:
                if d.MAC_ADDRESS == mac:
                    return d
            return False

    def make_edge_list(self):
        #[(1,2), (2,3)]
        edge_list = []

        device: Device
        for index, device in enumerate(self.devices):
            out_device: Device
            for out_device in device.devices_sent_to:                
                edge_list.append((index, self.get_index_by_mac(self.devices, out_device.MAC_ADDRESS)))

        return edge_list

    def plot_connections(self):
        graph = nx.DiGraph(self.make_edge_list())
        nx.draw_networkx(graph)
        plt.show()

    @staticmethod
    def get_devices_from_pcap(pcap: pyshark.FileCapture):
        """Turns a pcap into a list of Devices"""
        iterable_pcap = iter(pcap)
        device_dict = {}

        while True:
            try:
                packet: pyshark.packet.packet.Packet = next(iterable_pcap) 
            except StopIteration:
                break
            if has_given_layer(packet, "ETH"):
                src_mac = packet.layers[0].src
                dst_mac = packet.layers[0].dst
                print(device_dict)
                mac_list = [d.MAC_ADDRESS for d in device_dict.keys()]
                src = None
                dst = None

                if src_mac in mac_list:
                    src: Device = Network.get_device_by_mac(device_dict.keys(), src_mac)
                else:
                    src = Device(src_mac)
                    if has_given_layer(packet, "IP"):
                        src.ip_addresses.append(packet.layers[1].src)
                if dst_mac in mac_list:
                    dst: Device = Network.get_device_by_mac(device_dict.keys(), dst_mac)
                else:
                    dst = Device(dst_mac)
                    if has_given_layer(packet, "IP"):
                        dst.ip_addresses.append(packet.layers[1].dst)
                
                src.devices_sent_to = Network.add_to_device_dict(src.devices_sent_to, deepcopy(dst))
                dst.devices_received_from = Network.add_to_device_dict(src.devices_received_from, deepcopy(src))
                if src_mac in mac_list: 
                    device_dict = Network.add_to_device_dict(device_dict, deepcopy(src))
                if dst_mac not in mac_list: 
                    device_dict = Network.add_to_device_dict(device_dict, deepcopy(dst))

        return device_dict


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




with open('export','wb') as f:
    devices = Network.get_devices_from_pcap(pcap)
    net = Network(devices)
    print('Network object constructed.')
    dump(net, f)
    print('Network object dumped to file.')
quit()
with open('export','rb') as f:
    net: Network = load(f)
    print('Network object loaded from file.')
    net.plot_connections()


#print(get_all_addresses(pcap, "ETH"))
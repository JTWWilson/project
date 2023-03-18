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
from numpy import unique
import socket
from utils import get_manufacturer_from_mac, is_reserved_mac_address
from probe import add_device_to_database
import sqlite3
from device import Device

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
pcap = pyshark.FileCapture('andreeas-bigdownload.pcap')
DEFAULT_DB_NAME = 'devices.db'


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


def get_edges_from_pcap(pcap: pyshark.FileCapture):
        """Turns a pcap into a list of edges with widths"""
        iterable_pcap = iter(pcap)
        edges = {}
        macs_to_ip = {}

        while True:
            try:
                packet: pyshark.packet.packet.Packet = next(iterable_pcap) 
            except StopIteration:
                break
            if has_given_layer(packet, "ETH") and has_given_layer(packet, "IP"):
                src_mac = packet.layers[0].src
                dst_mac = packet.layers[0].dst
                
                if src_mac not in macs_to_ip:
                    macs_to_ip[src_mac] = packet.layers[1].src
                if dst_mac not in macs_to_ip:
                    macs_to_ip[dst_mac] = packet.layers[1].dst

                if (src_mac, dst_mac) in edges.keys():
                    edges[(src_mac, dst_mac)] += 1
                else:
                    edges[(src_mac, dst_mac)] = 1
        return edges, macs_to_ip


def get_devices_from_pcap(pcap: pyshark.FileCapture):
        """Turns a pcap into a list of edges with widths"""
        iterable_pcap = iter(pcap)
        devices = []
        macs_to_ip = {}

        # Loop through the pcap
        while True:
            try:
                packet: pyshark.packet.packet.Packet = next(iterable_pcap) 
            except StopIteration:
                break
            # If it's an IP packet with MAC address
            if has_given_layer(packet, "ETH") and has_given_layer(packet, "IP"):
                src_mac = packet.layers[0].src
                dst_mac = packet.layers[0].dst
                
                # Make a new device if the src mac hasn't been seen yet
                if src_mac not in devices:
                    new_device = Device(src_mac, [packet.layers[1].src])
                    new_device.devices_sent_to[dst_mac] = 1
                    devices.append(new_device)
                else:
                    # Increment the number of times this src device has sent to this dst 
                    existing_device: Device = devices[devices.index(src_mac)]
                    if dst_mac in existing_device.devices_sent_to:
                        existing_device.devices_sent_to[dst_mac] += 1
                    else:
                        existing_device.devices_sent_to[dst_mac] = 1

                # Make a new device if the dst mac hasn't been seen yet
                if dst_mac not in devices:
                    new_device = Device(dst_mac, [packet.layers[1].dst])
                    new_device.devices_received_from[src_mac] = 1
                    devices.append(new_device)
                else:
                    # Increment the number of times this dst device has been sent from this src
                    existing_device: Device = devices[devices.index(dst_mac)]
                    if src_mac in existing_device.devices_received_from:
                        existing_device.devices_received_from[src_mac] += 1
                    else:
                        existing_device.devices_received_from[src_mac] = 1

                # Add this packet to the edges list
                if (src_mac, dst_mac) in edges.keys():
                    edges[(src_mac, dst_mac)] += 1
                else:
                    # Or increment the weight of this edge if it's been seen before
                    edges[(src_mac, dst_mac)] = 1
        return edges, macs_to_ip


def get_name_from_mac(mac: str, device_db=DEFAULT_DB_NAME) -> str:
    """Returns a human readable name for a device from a mac address"""
    with sqlite3.connect(device_db) as connection:
        # Look for the MAC address in the device database
        name = connection.execute("SELECT name FROM DEVICES WHERE mac = '{}';".format(mac)).fetchall()
        # If it's in the database, return its name, else try to work out its name 
        if name != []:
            return name[0][0]

        try:
            # First try getting the device name
            name = socket.gethostbyaddr(macs_to_ip[mac])
            add_device_to_database(connection, mac, name[0])
            return name[0]
        except socket.herror:
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


def show_edges(edges, macs_to_ip):
    g = nx.DiGraph()
    sorted_macs = sorted(macs_to_ip)
    print(sorted_macs)
    node_labels = {}
    for i, mac in enumerate(sorted_macs):
        node_labels[mac] = get_name_from_mac(mac)
    
    for edge in edges:
        g.add_edge(edge[0], edge[1], weight=edges[edge])
    
    for mac in sorted_macs:
            g.add_node(mac)
    
    widths = nx.get_edge_attributes(g,'weight')
    print(widths)
    # normalise widths
    max_width = max(list(widths.values()))
    normalised_widths = []
    for k, v in widths.items():
        normalised_widths.append((v / max_width) * 5)
    print(widths)
    nx.draw_networkx(g, pos=nx.shell_layout(g), with_labels=False, width=normalised_widths)
    nx.draw_networkx_edge_labels(g,pos=nx.shell_layout(g),edge_labels=widths)
    nx.draw_networkx_labels(g, pos=nx.shell_layout(g), labels=node_labels, font_size=10)
    plt.show()


if __name__ == '__main__':
    print(get_all_addresses(pcap, "IP"))
    edges, macs_to_ip = get_edges_from_pcap(pcap)
    show_edges(edges, macs_to_ip)

    quit()
    with open('export','wb') as f:
        devices = Network.get_devices_from_pcap(pcap)
        net = Network(devices)
        print('Network object constructed.')
        dump(net, f)
        print('Network object dumped to file.')

    with open('export','rb') as f:
        net: Network = load(f)
        print('Network object loaded from file.')
        net.plot_connections()


    #print(get_all_addresses(pcap, "ETH"))
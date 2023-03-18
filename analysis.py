import pyshark
import typing
from typing_extensions import Literal
from dotenv import dotenv_values
import networkx as nx
import matplotlib.pyplot as plt
from pickle import dump, load
import sqlite3
from device import Device
from device_db_manager import get_device_name

config = dotenv_values(".env")
pcap = pyshark.FileCapture('andreeas-bigdownload.pcap')



class Network:
    def __init__(self, devices: typing.List[Device] =None) -> None:
        if devices is None:
            devices = list()
        self.devices: typing.List[Device] = devices

    @staticmethod
    def add_to_device_dict(dct, device) -> dict:
        if device.MAC_ADDRESS in dct.keys():
            dct[device.MAC_ADDRESS] += 1
        else:
            dct[device.MAC_ADDRESS] = 1
        return dct

    @staticmethod
    def get_index_by_mac(devices: typing.List[Device], mac: str) -> int:
        """Returns the index of the first Device in the list to have a matching MAC address"""
        for i, d in enumerate(devices):
            if d.MAC_ADDRESS == mac:
                return i
        return False

    @staticmethod
    def get_device_by_mac(devices: typing.List[Device], mac: str):
        """Returns first Device in the list to have a matching MAC address"""
        for d in devices:
            if d.MAC_ADDRESS == mac:
                return d
        return False

    def add_edges(self, g: nx.Graph) -> nx.Graph:
        """Adds packet traffic information from this Network onto an nx.Graph object"""
        for device in self.devices:
            for out_mac, weight in device.devices_sent_to.items():                
                g.add_edge(device.MAC_ADDRESS, out_mac, weight=weight)

        return g

    def add_nodes(self, g: nx.Graph) -> nx.Graph:
        for device in self.devices:
            g.add_node(device.MAC_ADDRESS, name=device.name)
        return g

    def plot_connections(self):
        g = nx.DiGraph()
        g = self.add_edges(g)
        g= self.add_nodes(g)

        widths = nx.get_edge_attributes(g,'weight')
        # normalise widths
        max_width = max(list(widths.values()))
        normalised_widths = []
        for k, v in widths.items():
            normalised_widths.append((v / max_width) * 5)

        node_names = nx.get_node_attributes(g,'name')
        print(node_names)

        nx.draw_networkx(g, pos=nx.shell_layout(g), with_labels=False, width=normalised_widths)
        nx.draw_networkx_edge_labels(g,pos=nx.shell_layout(g),edge_labels=widths)
        nx.draw_networkx_labels(g, pos=nx.shell_layout(g), labels=node_names, font_size=10)
        plt.show()


    @staticmethod
    def get_devices_from_pcap(pcap: pyshark.FileCapture):
        iterable_pcap = iter(pcap)
        devices = []

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
                # TODO: Make this less repetitive

                # Make a new device if the src mac hasn't been seen yet
                if src_mac not in devices:
                    new_device = Device(src_mac, [packet.layers[1].src])
                    new_device.devices_sent_to[dst_mac] = 1
                    devices.append(new_device)
                else:
                    # Increment the number of times this src device has sent to this dst 
                    existing_device: Device = devices[devices.index(src_mac)]
                    Device.add_device_to_dict(existing_device.devices_sent_to, dst_mac)

                # Make a new device if the dst mac hasn't been seen yet
                if dst_mac not in devices:
                    new_device = Device(dst_mac, [packet.layers[1].dst])
                    new_device.devices_received_from[src_mac] = 1
                    devices.append(new_device)
                else:
                    # Increment the number of times this dst device has been sent from this src
                    existing_device: Device = devices[devices.index(dst_mac)]
                    Device.add_device_to_dict(existing_device.devices_received_from, src_mac)

        return devices


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


if __name__ == '__main__':
    net = Network(Network.get_devices_from_pcap(pcap))
    net.plot_connections()
    #print(get_all_addresses(pcap, "IP"))
    #edges, macs_to_ip = get_edges_from_pcap(pcap)
    #show_edges(edges, macs_to_ip)

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
import pyshark
import typing
from typing_extensions import Literal
from dotenv import dotenv_values
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.text import Annotation
from pickle import dump, load
import mplcursors
from device import Device
from device_db_manager import get_device_name
from utils import is_local_ip_address, is_reserved_mac_address
import re

config = dotenv_values(".env")
pcap = pyshark.FileCapture('2023-3-18_16-22-52.pcap')



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
        router_mac, router_ip = Network.get_router_addresses()
        for device in self.devices:
            for out_mac in device.devices_sent_to.keys():
                total_packets = 0
                port_report = ""
                for out_port, weight in device.devices_sent_to[out_mac].items():
                    total_packets += weight
                    if out_port != -1:
                        port_report += "Port {}: {}pkts, ".format(out_port, weight)
                if (router_mac in out_mac or router_mac in device.MAC_ADDRESS) and out_mac != router_mac:
                    g.add_edge(device.MAC_ADDRESS, router_mac, dst_ports=port_report.rstrip(", "), weight=total_packets)                        
                    g.add_edge(router_mac, out_mac, dst_ports=port_report.rstrip(", "), weight=total_packets)
                else:
                    print(out_mac)
                    g.add_edge(device.MAC_ADDRESS, out_mac, dst_ports=port_report.rstrip(", "), weight=total_packets)

        return g

    def add_nodes(self, g: nx.Graph) -> nx.Graph:
        router_mac, router_ip = Network.get_router_addresses()
        for device in self.devices:
            if device.MAC_ADDRESS == router_mac:
                g.add_node(router_mac, name=device.name, color="black", local_addr="Router", layer=2)
                continue
            if is_reserved_mac_address(device.MAC_ADDRESS)[0]:
                colour = "green"
                local_addr = "Multicast"
                layer = 4
            elif all([is_local_ip_address(ip) for ip in device.ip_addresses]):
                colour = "blue"
                local_addr = "True"
                layer = 3
            elif all([not is_local_ip_address(ip) for ip in device.ip_addresses]):
                colour = "red"
                local_addr = "False"
                layer = 1
            g.add_node(device.MAC_ADDRESS, name=device.name, color=colour, local_addr=local_addr, layer=layer)
        return g

    def plot_connections(self):
        g = nx.DiGraph()
        g = self.add_edges(g)
        g = self.add_nodes(g)

        pos = nx.multipartite_layout(g, subset_key='layer')

        widths = nx.get_edge_attributes(g,'weight')
        # normalise widths
        max_width = max(list(widths.values()))
        normalised_widths = []
        for k, v in widths.items():
            normalised_widths.append((v / max_width) * 5)

        node_names = nx.get_node_attributes(g,'name')
        node_colours = nx.get_node_attributes(g,'color')
        print(node_names)

        dst_ports = nx.get_edge_attributes(g,'dst_ports')
        print(dst_ports)

        nodes = nx.draw_networkx_nodes(g, pos=pos, node_color=list(node_colours.values()))
        edges = nx.draw_networkx_edges(g, pos=pos, width=normalised_widths)
        nx.draw_networkx_edge_labels(g,pos=pos,edge_labels=dst_ports)
        nx.draw_networkx_labels(g, pos=pos, labels=node_names, font_size=10)
        
        def update_annot(sel):
            """
            Moves annotation to hovered node
            Inspired by https://stackoverflow.com/questions/70340499/networkx-and-matplotlib-how-to-access-node-attributes-and-show-them-as-annotati
            """
            node_index = sel.index
            node_name = list(g.nodes)[node_index]
            node_attr = g.nodes[node_name]
            text = node_name + '\n' + '\n'.join(f'{k}: {v}' for k, v in node_attr.items())
            sel.annotation: Annotation
            sel.annotation.set_text(text)
        
        def hide_annot(sel):
            """Hides annotation once cursor moves away"""
            sel.annotation: Annotation
            sel.annotation.set_visible(False)
        
        cursor = mplcursors.cursor(nodes, hover=2)
        cursor.connect('add', update_annot)
        cursor.connect('remove', hide_annot)

        cursor = mplcursors.cursor(edges, hover=2)
        cursor.connect('add', update_annot)

        plt.show()


    @staticmethod
    def get_router_addresses(host="8.8.8.8") -> "Tuple[str, str]":
        from subprocess import Popen, PIPE
        p = Popen(['tracert', '-h', '1', host], stdout=PIPE)
        while True:
            line = p.stdout.readline()
            if not line:
                break
            ips_ish = re.findall("\d+\.\d+\.\d+\.\d+",str(line))
            if ips_ish and host not in ips_ish:
                router_ip = ips_ish[0]
                break
        
        p = Popen(['arp', '-a', router_ip], stdout=PIPE)
        while True:
            line = p.stdout.readline()
            if not line:
                break
            mac_ish = re.findall("..-..-..-..-..-..",str(line))
            if mac_ish:
                return ':'.join(mac_ish[0].split('-')), router_ip


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
                src_ip = packet.layers[1].src
                dst_mac = packet.layers[0].dst
                dst_ip = packet.layers[1].dst
                if has_given_layer(packet, "TCP"):
                    dst_port = packet.layers[2].dstport
                else:
                    dst_port = -1

                if not is_local_ip_address(src_ip) and not is_reserved_mac_address(src_mac)[0]: 
                    src_mac = src_ip + "@" + src_mac
                if not is_local_ip_address(dst_ip) and not is_reserved_mac_address(dst_mac)[0]: 
                    dst_mac = dst_ip + "@" + dst_mac
                # TODO: Make this less repetitive

                # Make a new device if the src mac hasn't been seen yet
                if src_mac not in devices:
                    new_device = Device(src_mac, [packet.layers[1].src])
                    new_device.devices_sent_to[dst_mac] = {dst_port: 1}
                    devices.append(new_device)
                else:
                    # Increment the number of times this src device has sent to this dst 
                    existing_device: Device = devices[devices.index(src_mac)]
                    Device.add_packet_to_dict(existing_device.devices_sent_to, dst_mac, dst_port)

                # Make a new device if the dst mac hasn't been seen yet
                if dst_mac not in devices:
                    new_device = Device(dst_mac, [packet.layers[1].dst])
                    #new_device.devices_received_from[src_mac] = 1
                    devices.append(new_device)
                else:
                    # Increment the number of times this dst device has been sent from this src
                    existing_device: Device = devices[devices.index(dst_mac)]
                    #Device.add_device_to_dict(existing_device.devices_received_from, src_mac)

        return devices


def has_given_layer(
    packet: pyshark.packet.packet.Packet, 
    layer: Literal["ETH", "IP", "TCP"] = "ETH") -> bool:
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

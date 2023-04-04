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
from device_db_manager import get_device_name, get_router_list
from utils import is_local_ip_address, is_reserved_mac_address
import numpy as np
import sys

config = dotenv_values(".env")


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

    def add_edges(self, g: nx.Graph, allow_router: bool =True, allow_multicast: bool =True, allow_local: bool =True, allow_external: bool =True) -> nx.Graph:
        """Adds packet traffic information from this Network onto an nx.Graph object"""
        
        filtered_devices = list(filter((lambda x: x in g.nodes), self.devices))

        router_mac = ""
        router_list = get_router_list()
        print(router_list)
        for device in filtered_devices:
            if device in router_list:
                router_mac = device.MAC_ADDRESS

        for device in filtered_devices:
            for out_mac in device.devices_sent_to.keys():
                if out_mac in filtered_devices:
                    total_packets = 0
                    port_report = ""
                    for out_port, weight in device.devices_sent_to[out_mac].items():
                        total_packets += weight
                        #if out_port != -1:
                        #    port_report += "Port {}: {}pkts, ".format(out_port, weight)
                    if (router_mac in out_mac or router_mac in device.MAC_ADDRESS) and out_mac != router_mac:
                        g.add_edge(device.MAC_ADDRESS, router_mac, dst_ports=port_report.rstrip(", "), weight=total_packets)                        
                        g.add_edge(router_mac, out_mac, dst_ports=port_report.rstrip(", "), weight=total_packets)
                    else:
                        g.add_edge(device.MAC_ADDRESS, out_mac, dst_ports=port_report.rstrip(", "), weight=total_packets)

        return g

    def add_edges_ignore_router(self, g: nx.Graph, allow_router: bool =True, allow_multicast: bool =True, allow_local: bool =True, allow_external: bool =True) -> nx.Graph:
        """Adds packet traffic information from this Network onto an nx.Graph object"""
        router_mac = None
        router_list = get_router_list()
        for device in filter((lambda x: x in g.nodes), self.devices): 
            if device in router_list:
                router_mac = device.MAC_ADDRESS


        for device in self.devices:
            for out_mac in device.devices_sent_to.keys():
                if not allow_router and router_mac in (device.MAC_ADDRESS, out_mac):
                    continue
                if not allow_multicast and (is_reserved_mac_address(device.MAC_ADDRESS)[0] or is_reserved_mac_address(out_mac)[0]):
                    continue
                if not allow_local and all([is_local_ip_address(ip) for ip in device.ip_addresses]):
                    continue
                if not allow_external and all([not is_local_ip_address(ip) for ip in device.ip_addresses]):
                    continue
                total_packets = 0
                port_report = ""
                for out_port, weight in device.devices_sent_to[out_mac].items():
                    total_packets += weight
                    if out_port != -1:
                        port_report += "Port {}: {}pkts, ".format(out_port, weight)
                    g.add_edge(device.MAC_ADDRESS, out_mac, dst_ports=port_report.rstrip(", "), weight=total_packets)

        return g

    def add_nodes(self, g: nx.Graph, allow_router: bool =True, allow_multicast: bool =True, allow_local: bool =True, allow_external: bool =True) -> nx.Graph:
        router_list = get_router_list()
        for device in self.devices:
            if allow_router and device.MAC_ADDRESS in router_list:
                g.add_node(device.MAC_ADDRESS, name=device.name, color="black", local_addr="Router", layer=2, os_guess=device.os_guess.__repr__())
                continue
            if is_reserved_mac_address(device.MAC_ADDRESS)[0]:
                if allow_multicast:
                    g.add_node(device.MAC_ADDRESS, name=device.name, color="green", local_addr="Multicast", layer=4, os_guess=device.os_guess.__repr__())
            elif all([is_local_ip_address(ip) for ip in device.ip_addresses]):
                if allow_local:
                    g.add_node(device.MAC_ADDRESS, name=device.name, color="blue", local_addr="Local", layer=3, os_guess=device.os_guess.__repr__())
            elif all([not is_local_ip_address(ip) for ip in device.ip_addresses]):
                if allow_external:
                    g.add_node(device.MAC_ADDRESS, name=device.name, color="red", local_addr="External", layer=1, os_guess=device.os_guess.__repr__())
        return g

    def plot_connections(self, layout):
        if layout == "multipartite":
            self.plot_multipartite()


    def plot_custom(self): #WIP
        g = nx.DiGraph()

        g = self.add_nodes(g, allow_router=True)
        g = self.add_edges(g)

        pos = nx.multipartite_layout(g, subset_key='layer')

        x_shuffle = 0
        router_list = get_router_list()
        for node, (x,y) in pos.items():
            if node in router_list:
                pos[node] = np.array([x*2, y])
                x_shuffle = x
                break
        
        outside_network = nx.DiGraph()
        outside_network = self.add_nodes(outside_network, allow_external=True, allow_router=True, allow_local=False, allow_multicast=False)
        outside_network = self.add_edges(outside_network)
        outside_pos = nx.multipartite_layout(outside_network, subset_key="layer")

        inside_network = nx.DiGraph()
        inside_network = self.add_nodes(inside_network, allow_external=False, allow_router=True, allow_local=True, allow_multicast=True)
        inside_network = self.add_edges(inside_network)
        inside_pos = nx.spring_layout(inside_network)

        pos = nx.multipartite_layout(g, subset_key='layer')

        normalised_widths = self.normalise_widths(nx.get_edge_attributes(g,'weight'))

        node_names = nx.get_node_attributes(g,'name')
        node_colours = nx.get_node_attributes(g,'color')

        dst_ports = nx.get_edge_attributes(g,'dst_ports')

        nodes = nx.draw_networkx_nodes(g, pos=pos, node_color=list(node_colours.values()))
        edges = nx.draw_networkx_edges(g, pos=pos, width=normalised_widths)
        nx.draw_networkx_edge_labels(g,pos=pos,edge_labels=dst_ports)
        nx.draw_networkx_labels(g, pos=pos, labels=node_names, font_size=10)
        self.add_hover_popup(g, nodes)

        plt.show()

    def add_hover_popup(self, g: nx.Graph, nodes):
        """Adds a popup to nodes which displays information about the node when it is hovered over."""
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


    def normalise_widths(self, widths) -> list:
        max_width = max(list(widths.values()))
        normalised_widths = []
        for k, v in widths.items():
            normalised_widths.append((v / max_width) * 5)
        return normalised_widths

    def plot_multipartite(self):
        g = nx.DiGraph()

        g = self.add_nodes(g, allow_router=True)
        g = self.add_edges(g)


        internal_net = nx.DiGraph()

        internal_net = self.add_nodes(internal_net, allow_router=False, allow_local=True, allow_external=False, allow_multicast=False)
        internal_net = self.add_edges(internal_net)
        internal_pos = nx.shell_layout(internal_net)
        internal_nodes = internal_net.nodes

        #layout = CommunityLayout(g, layout_algorithm=nx.bipartite_layout, layout_kwargs={})
        #pos = layout.full_positions
        pos = nx.multipartite_layout(g, subset_key='layer')

        # get distance between x_min and x_max
        x_min = min([x for x, y in pos.values()])
        x_max = max([x for x, y in pos.values()])

        router_list = get_router_list()

        
        for node, (x,y) in pos.items():
            if node in router_list:
                pos[node] = np.array([x_min*0.3, y])
                continue
            if node in internal_nodes:
                pos[node] = np.array([internal_pos[node][0] * 0.3 * x_max + 0.35 * x_max, internal_pos[node][1]]) 

        label_pos = {}
        for node, (x,y) in pos.items():
            label_pos[node] = (x, y-0.08)

        normalised_widths = self.normalise_widths(nx.get_edge_attributes(g,'weight'))

        node_names = nx.get_node_attributes(g,'name')
        node_colours = nx.get_node_attributes(g,'color')

        dst_ports = nx.get_edge_attributes(g,'dst_ports')

        nodes = nx.draw_networkx_nodes(g, pos=pos, node_color=list(node_colours.values()))
        edges = nx.draw_networkx_edges(g, pos=pos, width=normalised_widths)
        nx.draw_networkx_edge_labels(g,pos=pos,edge_labels=dst_ports)
        nx.draw_networkx_labels(g, pos=label_pos, labels=node_names, font_size=10)
        self.add_hover_popup(g, nodes)

        plt.show()


    @staticmethod
    def get_devices_from_pcap(pcap: pyshark.capture.capture.Capture):
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
                    new_device = Device(src_mac, [str(packet.layers[1].src)])
                    new_device.devices_sent_to[dst_mac] = {dst_port: 1}
                    devices.append(new_device)
                else:
                    # Increment the number of times this src device has sent to this dst 
                    existing_device: Device = devices[devices.index(src_mac)]
                    Device.add_packet_to_dict(existing_device.devices_sent_to, dst_mac, dst_port)

                # Make a new device if the dst mac hasn't been seen yet
                if dst_mac not in devices:
                    new_device = Device(dst_mac, [str(packet.layers[1].dst)])
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
    if len(sys.argv) == 2:
        pcap_path = sys.argv[1]
    else:
        quit("No path to a pcap was given.")
    pcap = pyshark.FileCapture(pcap_path)
    net = Network(Network.get_devices_from_pcap(pcap))
    net.plot_connections("multipartite")
    """
    with open('export','wb') as f:
        devices = Network.get_devices_from_pcap(pcap)
        net = Network(devices)
        print('Network object constructed.')
        dump(net, f)
        print('Network object dumped to file.')

    with open('export','rb') as f:
        net: Network = load(f)
        print('Network object loaded from file.')
        net.plot_connections("multipartite")
    """
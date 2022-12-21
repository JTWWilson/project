import pyshark
import typing
from typing_extensions import Literal

# Convert to iterable for efficiency
pcap = pyshark.FileCapture('firstRead.pcap')


class Device:
    def __init__(self, mac_addr) -> None:
        self.MAC_ADDRESS = mac_addr
        self.ip_addresses = []
        self.devices_sent_to = []
        self.devices_received_from = []


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
            print(packet)
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
            src = packet.layers[0].src
            dst = packet.layers[0].dst
            # If source device is new, create Device object and add it to ret
            if src not in [d.MAC_ADDRESS for d in ret]:
                new_device = Device(src)
                if has_given_layer(packet, "IP"):
                    new_device.ip_addresses.append(packet.layers[1].src)
                # If destination device is also new, create Device object and add it to ret
                if dst not in [d.MAC_ADDRESS for d in ret]:                   
                    other_new_device = Device(dst)
                    if has_given_layer(packet, "IP"):
                        other_new_device.ip_addresses.append(packet.layers[1].dst)
                    new_device.devices_sent_to.append(other_new_device)
                    other_new_device.devices_sent_to.append(new_device)
                ret.append(new_device)
            
            

        i += 1

    return ret


print(get_all_addresses(pcap, "ETH"))
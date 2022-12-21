import pyshark

# Convert to iterable for efficiency
pcap = iter(pyshark.FileCapture('firstRead.pcap'))


def has_ip_layer(packet: pyshark.packet.packet.Packet) -> bool:
    try:
        ip = packet['IP']
        return True
    except KeyError:
        return False

ip_addresses = set()

i = 0
while True: #i < 50:
    try:
        packet: pyshark.packet.packet.Packet = next(pcap) 
    except StopIteration:
        break
    if has_ip_layer(packet):
        # print(packet.layers)
        ip_src = packet.layers[1].src
        ip_dst = packet.layers[1].dst
        for addr in (ip_src, ip_dst):
            if addr not in ip_addresses:
                ip_addresses.add(addr)

    i += 1

print(ip_addresses)
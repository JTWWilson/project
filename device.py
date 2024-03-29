from device_db_manager import get_device_name, get_os_guess

class Device:
    """Represents a device with a MAC address as a primary key"""
    def __init__(self, mac_addr, ip_addresses: list=None) -> None:
        self.MAC_ADDRESS = mac_addr
        self.ip_addresses = ip_addresses
        self.devices_sent_to = {}
        self.devices_received_from = {} # TODO: Make MAC Address class
        self.name = get_device_name(mac_addr)
        self.os_guess = get_os_guess(mac_addr)

    @staticmethod
    def add_packet_to_dict(dct: dict, mac: str, dest_port: int) -> dict:
        """dtc strucure:
        {
            "00:00:00:00:00:00" : {1: 3}
        }"""
        if mac in dct.keys():
            if dest_port in dct[mac].keys():
                dct[mac][dest_port] += 1
            else:
                dct[mac] = {dest_port: 1}
        else:
            dct[mac] = {dest_port: 1}
        return dct

    def __repr__(self) -> str:
        return self.MAC_ADDRESS

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.MAC_ADDRESS == other
        elif isinstance(other, Device):
            return self.MAC_ADDRESS == other.MAC_ADDRESS
        return False

    def __lt__(self, other) -> bool:
        return self.MAC_ADDRESS < other.MAC_ADDRESS
    
    def __gt__(self, other) -> bool:
        return self.MAC_ADDRESS > other.MAC_ADDRESS

    def __le__(self, other) -> bool:
        return self.MAC_ADDRESS <= other.MAC_ADDRESS
    
    def __ge__(self, other) -> bool:
        return self.MAC_ADDRESS >= other.MAC_ADDRESS

    def __hash__(self) -> int:
        return hash(self.MAC_ADDRESS)
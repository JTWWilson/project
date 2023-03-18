class Device:
    """Represents a device with a MAC address as a primary key"""
    def __init__(self, mac_addr, ip_addresses: list=None) -> None:
        self.MAC_ADDRESS = mac_addr
        self.ip_addresses = ip_addresses
        self.devices_sent_to = {}
        self.devices_received_from = {}

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
def is_local_ip_address(ip_address: str) -> bool:
    """Returns True if the ip address is in the local address range."""
    if ip_address.startswith('10.') or ip_address.startswith('192.168'):
        return True
    if 16 <= int(ip_address.split('.')[1]) < 32:
        return True
    return False
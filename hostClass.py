class HostUp:
    def __init__(self, ip:str, mac_addr: str = None, os: str = None):
        self.ip = ip
        self.mac_addr = mac_addr
        self.os = os
        self.ports = []

    def add_ip(self, ip):
        self.ip = ip

    def add_mac(self, mac_addr):
        self.mac_addr = mac_addr

    def add_os(self, os):
        self.os = os

    def add_port(self, port):
        self.ports.append(port)

    def get_ip(self):
        return self.ip

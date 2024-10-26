import socket
import struct
import ipaddress
import re
from cryptography.fernet import Fernet
import logging
from scapy.all import ARP, sniff
import threading

class Firewall:
    def __init__(self):
        self.rules = []
        self.blocked_ips = set()
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.mac_ip_table = {}
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(filename='firewall.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def add_rule(self, protocol, src_ip, src_port, dst_ip, dst_port, action):
        self.rules.append({
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'action': action
        })
        logging.info(f"Rule added: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {action}")

    def check_packet(self, packet):
        protocol = packet['protocol']
        src_ip = packet['src_ip']
        src_port = packet['src_port']
        dst_ip = packet['dst_ip']
        dst_port = packet['dst_port']

        for rule in self.rules:
            if (rule['protocol'] == protocol or rule['protocol'] == 'any') and \
               self.ip_match(rule['src_ip'], src_ip) and \
               self.port_match(rule['src_port'], src_port) and \
               self.ip_match(rule['dst_ip'], dst_ip) and \
               self.port_match(rule['dst_port'], dst_port):
                logging.info(f"Packet {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {rule['action']}")
                return rule['action']

        logging.info(f"Packet {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} allowed (default)")
        return 'allow'

    def ip_match(self, rule_ip, packet_ip):
        if rule_ip == 'any':
            return True
        if '/' in rule_ip:  # CIDR notation
            return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip)
        return rule_ip == packet_ip

    def port_match(self, rule_port, packet_port):
        if rule_port == 'any':
            return True
        if '-' in str(rule_port):  # Port range
            start, end = map(int, rule_port.split('-'))
            return start <= packet_port <= end
        return int(rule_port) == packet_port

    def protect_against_arp_spoofing(self):
        def arp_monitor_callback(pkt):
            if ARP in pkt and pkt[ARP].op in (1, 2):  # ARP request or reply
                src_mac = pkt[ARP].hwsrc
                src_ip = pkt[ARP].psrc
                if src_mac in self.mac_ip_table:
                    if self.mac_ip_table[src_mac] != src_ip:
                        logging.warning(f"Potential ARP spoofing detected: {src_mac} - {src_ip}")
                        self.blocked_ips.add(src_ip)
                else:
                    self.mac_ip_table[src_mac] = src_ip

        sniff(prn=arp_monitor_callback, filter="arp", store=0)

    def start_arp_protection(self):
        arp_thread = threading.Thread(target=self.protect_against_arp_spoofing)
        arp_thread.daemon = True
        arp_thread.start()

    def protect_against_sql_injection(self, query):
        sql_patterns = [
            r'\bUNION\b',
            r'\bSELECT\b',
            r'\bFROM\b',
            r'\bWHERE\b',
            r'--',
            r'/\*.*\*/',
            r';',
            r"'",
            r'"'
        ]
        for pattern in sql_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                logging.warning(f"Potential SQL injection detected: {query}")
                return 'block'
        return 'allow'

    def encrypt_data(self, data):
        return self.fernet.encrypt(data.encode())

    def decrypt_data(self, encrypted_data):
        return self.fernet.decrypt(encrypted_data).decode()

# Example usage
if __name__ == "__main__":
    firewall = Firewall()

    # Add some rules
    firewall.add_rule('tcp', '192.168.1.0/24', 80, 'any', 'any', 'allow')
    firewall.add_rule('udp', 'any', 'any', '10.0.0.1', '53', 'block')
    firewall.add_rule('tcp', 'any', 'any', '192.168.1.100', '3306', 'allow')

    # Start ARP spoofing protection
    firewall.start_arp_protection()

    # Check a packet
    packet = {
        'protocol': 'tcp',
        'src_ip': '192.168.1.100',
        'src_port': 12345,
        'dst_ip': '10.0.0.2',
        'dst_port': 80
    }

    result = firewall.check_packet(packet)
    print(f"Packet action: {result}")

    # Test SQL injection protection
    query = "SELECT * FROM users WHERE username = 'admin' OR '1'='1'"
    sql_result = firewall.protect_against_sql_injection(query)
    print(f"SQL query action: {sql_result}")

    # Test encryption
    original_data = "Sensitive information"
    encrypted = firewall.encrypt_data(original_data)
    decrypted = firewall.decrypt_data(encrypted)
    print(f"Original: {original_data}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")

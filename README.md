# Math/BC Server Firewall

This project implements a comprehensive firewall for the Math/BC server, addressing specific requirements and providing protection against common network attacks.

## Features

1. Filtering of incoming and outgoing network traffic based on predefined rules
2. Support for IP ranges (CIDR notation) and port ranges in rules
3. Protection against ARP spoofing attacks
4. Protection against SQL injection attacks
5. Secure communication using encryption for data transmission
6. Logging of firewall activities and security events

## Requirements

- Python 3.7+
- cryptography library
- scapy library

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/RBalajisrinath/Mini-Project--Math-BC-Server-Firewall.git
   cd mathbc-server-firewall
   ```

2. Install the required dependencies:
   ```
   pip install cryptography scapy
   ```

## Usage

1. Import the Firewall class from the `firewall.py` file:
   ```python
   from firewall import Firewall
   ```

2. Create a Firewall instance:
   ```python
   firewall = Firewall()
   ```

3. Add rules to the firewall:
   ```python
   firewall.add_rule('tcp', '192.168.1.0/24', 80, 'any', 'any', 'allow')
   firewall.add_rule('udp', 'any', 'any', '10.0.0.1', '53', 'block')
   firewall.add_rule('tcp', 'any', 'any', '192.168.1.100', '3306', 'allow')
   ```

4. Start ARP spoofing protection:
   ```python
   firewall.start_arp_protection()
   ```

5. Check packets against the firewall rules:
   ```python
   packet = {
       'protocol': 'tcp',
       'src_ip': '192.168.1.100',
       'src_port': 12345,
       'dst_ip': '10.0.0.2',
       'dst_port': 80
   }
   result = firewall.check_packet(packet)
   print(f"Packet action: {result}")
   ```

6. Use SQL injection protection:
   ```python
   query = "SELECT * FROM users WHERE username = 'admin' OR '1'='1'"
   sql_result = firewall.protect_against_sql_injection(query)
   print(f"SQL query action: {sql_result}")
   ```

7. Use data encryption:
   ```python
   original_data = "Sensitive information"
   encrypted = firewall.encrypt_data(original_data)
   decrypted = firewall.decrypt_data(encrypted)
   ```

## Deployment

To deploy this firewall on the Math/BC server:

1. Copy the `firewall.py` file to the server.
2. Modify the server's network configuration to route all incoming and outgoing traffic through the firewall.
3. Implement the firewall in the server's main application or as a separate service.
4. Ensure that the firewall is initialized with appropriate rules for the Math/BC server's specific requirements.
5. Configure the logging settings to store logs in a secure location.

## Key Components

1. **Rule-based Packet Filtering**: The `check_packet` method allows for sophisticated rule matching, including support for IP ranges (CIDR notation) and port ranges.

2. **ARP Spoofing Protection**: The `protect_against_arp_spoofing` method continuously monitors ARP traffic to detect potential spoofing attempts.

3. **SQL Injection Protection**: The `protect_against_sql_injection` method uses regex patterns to identify potential SQL injection attempts in queries.

4. **Secure Communication**: The `encrypt_data` and `decrypt_data` methods use the Fernet symmetric encryption from the `cryptography` library to secure data transmission.

5. **Logging**: The firewall logs all activities and security events, which can be used for auditing and threat analysis.

## Limitations and Future Improvements

While this implementation provides a solid foundation, there are several areas for potential improvement:

- Implement stateful packet inspection for more accurate traffic analysis.
- Add support for application-layer filtering.
- Enhance the ARP spoofing protection with more sophisticated detection algorithms.
- Implement a graphical user interface for easier rule management.
- Add support for intrusion detection and prevention capabilities.
- Optimize performance for high-traffic environments.
- Implement additional security features specific to the Math/BC server's needs.

from scapy.all import *
import csv
import re

# Define a regex pattern for detecting SQL injection indicators
sql_injection_pattern = re.compile(r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|;|--|\bOR\b|\bAND\b)", re.IGNORECASE)

# Function to process each packet
def process_packet(packet):
    # Initialize the packet info list
    packet_info = [
        packet.time,  # Timestamp
        packet[IP].src if IP in packet else 'N/A',  # Source IP
        packet[IP].dst if IP in packet else 'N/A',  # Destination IP
        len(packet),  # Length of the packet
        packet[TCP].sport if TCP in packet else 'N/A',  # Source port
        packet[TCP].dport if TCP in packet else 'N/A',  # Destination port
        packet[TCP].flags if TCP in packet else 'N/A',  # TCP flags
    ]

    # Check if the packet has a Raw layer (which contains the HTTP payload)
    if packet.haslayer(Raw):
        # Convert the payload to a readable format
        payload = packet[Raw].load.hex()  # Convert to hexadecimal format
        
        # Check for SQL injection patterns in the payload
        if sql_injection_pattern.search(bytes.fromhex(payload).decode('utf-8', errors='ignore')):
            packet_info.append('Potential SQL Injection Detected')
        else:
            packet_info.append('No SQL Injection')

        packet_info.append(payload)  # Append the payload to the info list
    else:
        packet_info.extend(['N/A', 'N/A'])  # No payload available

    # Write to CSV
    with open('packets.csv', 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(packet_info)

# Create CSV file and write header
with open('packets.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Length', 
                     'Source Port', 'Destination Port', 'TCP Flags', 
                     'SQL Injection Detected', 'Payload'])

# Start sniffing and process packets
sniff(iface='eth0', prn=process_packet)

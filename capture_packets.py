from scapy.all import *
import csv

# Function to process each packet
def process_packet(packet):
    # Extract desired fields
    packet_info = [
        packet.time,
        packet[IP].src if IP in packet else 'N/A',
        packet[IP].dst if IP in packet else 'N/A',
        len(packet)
    ]
    # Write to CSV
    with open('packets.csv', 'a') as f:
        writer = csv.writer(f)
        writer.writerow(packet_info)

# Create CSV file and write header
with open('packets.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Length'])

# Start sniffing and process packets
sniff(iface='eth0', prn=process_packet)

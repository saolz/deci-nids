from scapy.all import sniff
import polars as pl
from datetime import datetime
import statistics
import time
import threading

# Define a dictionary to store flow data
flow_data = {}
stop_event = threading.Event()

def process_packet(packet):
    global flow_data

    if packet.haslayer('IP'):
        # Extract information from the packet
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        length = len(packet)
        timestamp = datetime.now()

        # Initialize flow key based on src/dst IP and protocol
        flow_key = (src_ip, dst_ip, protocol)

        # Initialize flow data if not present
        if flow_key not in flow_data:
            flow_data[flow_key] = {
                'start_time': timestamp,
                'total_fwd_packets': 0,
                'total_bwd_packets': 0,
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
                'packet_times': [],
                'packet_lengths': [],
                'fwd_flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0},
                'bwd_flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0}
            }

        # Update flow data
        flow = flow_data[flow_key]

        # Update counts and lists based on the packet's direction (example condition for forward and backward)
        if src_ip == packet['IP'].src:  # Forward packets
            flow['total_fwd_packets'] += 1
            flow['fwd_packet_lengths'].append(length)
        else:  # Backward packets
            flow['total_bwd_packets'] += 1
            flow['bwd_packet_lengths'].append(length)

        flow['packet_times'].append(timestamp)
        flow['packet_lengths'].append(length)

        # TCP flags (if TCP packet)
        if packet.haslayer('TCP'):
            tcp_flags = packet['TCP'].flags
            if src_ip == packet['IP'].src:  # Forward direction
                flow['fwd_flags']['FIN'] += int(tcp_flags & 0x01 != 0)
                flow['fwd_flags']['SYN'] += int(tcp_flags & 0x02 != 0)
                flow['fwd_flags']['RST'] += int(tcp_flags & 0x04 != 0)
                flow['fwd_flags']['PSH'] += int(tcp_flags & 0x08 != 0)
                flow['fwd_flags']['ACK'] += int(tcp_flags & 0x10 != 0)
                flow['fwd_flags']['URG'] += int(tcp_flags & 0x20 != 0)
            else:  # Backward direction
                flow['bwd_flags']['FIN'] += int(tcp_flags & 0x01 != 0)
                flow['bwd_flags']['SYN'] += int(tcp_flags & 0x02 != 0)
                flow['bwd_flags']['RST'] += int(tcp_flags & 0x04 != 0)
                flow['bwd_flags']['PSH'] += int(tcp_flags & 0x08 != 0)
                flow['bwd_flags']['ACK'] += int(tcp_flags & 0x10 != 0)
                flow['bwd_flags']['URG'] += int(tcp_flags & 0x20 != 0)

def calculate_features():
    features = []
    for flow_key, data in flow_data.items():
        duration = (datetime.now() - data['start_time']).total_seconds()
        total_fwd_packets = data['total_fwd_packets']
        total_bwd_packets = data['total_bwd_packets']
        fwd_packet_lengths = data['fwd_packet_lengths']
        bwd_packet_lengths = data['bwd_packet_lengths']
        total_packets = total_fwd_packets + total_bwd_packets
        total_bytes = sum(data['packet_lengths'])

        # Forward packet length statistics
        fwd_packet_length_max = max(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_min = min(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_mean = sum(fwd_packet_lengths) / len(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_std = statistics.stdev(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0

        # Backward packet length statistics
        bwd_packet_length_max = max(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_min = min(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_mean = sum(bwd_packet_lengths) / len(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_std = statistics.stdev(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0

        # Flow-level features
        flow_bytes_per_s = total_bytes / duration if duration > 0 else 0
        flow_packets_per_s = total_packets / duration if duration > 0 else 0

        # Inter-arrival times (IAT)
        iat_list = [(data['packet_times'][i] - data['packet_times'][i-1]).total_seconds() 
                    for i in range(1, len(data['packet_times']))]
        iat_mean = sum(iat_list) / len(iat_list) if iat_list else 0
        iat_std = statistics.stdev(iat_list) if len(iat_list) > 1 else 0
        iat_max = max(iat_list) if iat_list else 0
        iat_min = min(iat_list) if iat_list else 0

        # Flag counts (TCP)
        fwd_flags = data['fwd_flags']
        bwd_flags = data['bwd_flags']

        features.append({
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'protocol': flow_key[2],
            'flow_duration': duration,
            'total_fwd_packets': total_fwd_packets,
            'total_bwd_packets': total_bwd_packets,
            'fwd_packet_length_max': fwd_packet_length_max,
            'fwd_packet_length_min': fwd_packet_length_min,
            'fwd_packet_length_mean': fwd_packet_length_mean,
            'fwd_packet_length_std': fwd_packet_length_std,
            'bwd_packet_length_max': bwd_packet_length_max,
            'bwd_packet_length_min': bwd_packet_length_min,
            'bwd_packet_length_mean': bwd_packet_length_mean,
            'bwd_packet_length_std': bwd_packet_length_std,
            'flow_bytes_per_s': flow_bytes_per_s,
            'flow_packets_per_s': flow_packets_per_s,
            'iat_mean': iat_mean,
            'iat_std': iat_std,
            'iat_max': iat_max,
            'iat_min': iat_min,
            'fwd_fin_count': fwd_flags['FIN'],
            'fwd_syn_count': fwd_flags['SYN'],
            'fwd_rst_count': fwd_flags['RST'],
            'fwd_psh_count': fwd_flags['PSH'],
            'fwd_ack_count': fwd_flags['ACK'],
            'fwd_urg_count': fwd_flags['URG'],
            'bwd_fin_count': bwd_flags['FIN'],
            'bwd_syn_count': bwd_flags['SYN'],
            'bwd_rst_count': bwd_flags['RST'],
            'bwd_psh_count': bwd_flags['PSH'],
            'bwd_ack_count': bwd_flags['ACK'],
            'bwd_urg_count': bwd_flags['URG']
        })

    # Create a Polars DataFrame from the features list
    df = pl.DataFrame(features)
    return df

def periodic_task():
    """Function to capture and print features periodically."""
    global stop_event
    start_time = time.time()
    
    while not stop_event.is_set():
        current_time = time.time()
        if current_time - start_time >= 10:
            # Calculate features and print DataFrame
            features_df = calculate_features()
            print("Features DataFrame:")
            print(features_df)

            # Save to CSV
            features_df.write_csv("packet.csv")
            
            # Reset start time for the next interval
            start_time = current_time

        # Continue packet sniffing
        sniff(prn=process_packet, timeout=1, store=0)  # Adjust timeout as needed

def main():
    global stop_event
    print('Starting packet capture...')

    # Start packet capturing in a separate thread
    capture_thread = threading.Thread(target=periodic_task)
    capture_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping packet capture...")
        stop_event.set()
        capture_thread.join()  # Ensure the thread has finished

if __name__ == '__main__':
    main()


import time
import random
import os
from scapy.all import IP, TCP, UDP, Raw, wrpcap, IPv6, Packet

# Define some common IPs and ports for variety
SRC_IPS_V4 = ["192.168.1.100", "10.0.0.50", "172.16.0.20"]
DST_IPS_V4 = ["192.168.1.1", "8.8.8.8", "208.67.222.222"] # Include a public DNS server
SRC_IPS_V6 = ["2001:db8::1", "fd00::100"]
DST_IPS_V6 = ["2001:db8::ffff", "2606:4700::1111"] # Cloudflare DNS IPv6

MIN_PORT = 1024
MAX_PORT = 65535
HTTP_PORT = 80
HTTPS_PORT = 443
DNS_PORT = 53

# Output directory for generated pcaps
OUTPUT_DIR = "data/in"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_flow(flow_type="tcp_short", num_packets=10, ip_version="ipv4", src_ip=None, dst_ip=None, src_port=None, dst_port=None, start_time=None, iat_mean_micros=1000, payload_size_mean=50, include_flags=True):
    """Generates packets for a single flow."""
    packets = []
    if start_time is None:
        start_time = time.time() # Start time in seconds

    current_time = start_time
    flow_src_ip = src_ip if src_ip else (random.choice(SRC_IPS_V4) if ip_version == "ipv4" else random.choice(SRC_IPS_V6))
    flow_dst_ip = dst_ip if dst_ip else (random.choice(DST_IPS_V4) if ip_version == "ipv4" else random.choice(DST_IPS_V6))
    flow_src_port = src_port if src_port is not None else random.randint(MIN_PORT, MAX_PORT)
    flow_dst_port = dst_port if dst_port is not None else random.choice([HTTP_PORT, HTTPS_PORT, DNS_PORT, random.randint(MIN_PORT, MAX_PORT)])

    # Determine packet directionality (simple random for now, can be improved)
    is_forward = random.choice([True, False])

    # TCP state tracking (simplified)
    tcp_seq = random.randint(0, 2**32 - 1)
    tcp_ack = random.randint(0, 2**32 - 1)

    for i in range(num_packets):
        payload_size = max(0, int(random.gauss(payload_size_mean, payload_size_mean/2))) # Ensure non-negative size

        if is_forward:
            ip_layer = IP(src=flow_src_ip, dst=flow_dst_ip) if ip_version == "ipv4" else IPv6(src=flow_src_ip, dst=flow_dst_ip)
            src_p, dst_p = flow_src_port, flow_dst_port
        else:
            ip_layer = IP(src=flow_dst_ip, dst=flow_src_ip) if ip_version == "ipv4" else IPv6(src=flow_dst_ip, dst=flow_src_ip)
            src_p, dst_p = flow_dst_port, flow_src_port # Reverse ports for backward packets

        transport_layer = None
        if flow_type.startswith("tcp"):
            # Simulate basic TCP flags and sequence/ack numbers
            flags = ""
            if i == 0: # First packet
                flags = "S" # SYN
                tcp_seq += 1 # SYN consumes a sequence number
            elif i == 1 and flow_type != "tcp_syn_flood": # Second packet (simulate handshake response)
                 # If bidirectional, the second packet is likely backward SYN-ACK
                 if not is_forward:
                      flags = "SA" # SYN-ACK
                      # Simplified ack/seq update
                      temp_ack = tcp_seq + 1
                      tcp_seq = tcp_ack
                      tcp_ack = temp_ack
                 else:
                      flags = "A" # ACK
                      tcp_ack = tcp_seq + payload_size # Acknowledge data from previous packet

            elif i == num_packets - 1 and include_flags: # Last packet
                 if flow_type == "tcp_fin_terminate":
                      flags = "FA" # FIN-ACK
                 elif flow_type == "tcp_rst_terminate":
                      flags = "R" # RST
                 else:
                      flags = "A" # Standard ACK
                 tcp_ack = tcp_seq + payload_size # Acknowledge data from previous packet

            else:
                flags = "A" # Standard data ACK
                tcp_ack = tcp_seq + payload_size # Acknowledge data from previous packet
                if include_flags and random.random() < 0.1: # Occasionally include PSH or URG
                     flags += "P" if random.random() < 0.5 else "U"


            transport_layer = TCP(sport=src_p, dport=dst_p, flags=flags, seq=tcp_seq, ack=tcp_ack, window=random.randint(1024, 65535))
            if flags != "S" and flags != "SA" and payload_size > 0: # Data packets update seq
                 tcp_seq += payload_size


        elif flow_type.startswith("udp"):
            transport_layer = UDP(sport=src_p, dport=dst_p)

        if transport_layer:
            # Add payload if size > 0
            if payload_size > 0:
                 packet = ip_layer / transport_layer / Raw(load='\x00' * payload_size)
            else:
                 packet = ip_layer / transport_layer
        else:
             # Handle other protocols if needed, for this example, we only generate TCP/UDP
             continue # Skip if no transport layer could be created


        # Manually set packet timestamp in seconds (scapy requires float)
        packet.time = current_time

        packets.append(packet)

        # Simulate Inter-Arrival Time (IAT) in microseconds, convert to seconds for adding to time
        iat_micros = max(0, int(random.gauss(iat_mean_micros, iat_mean_micros/4))) # Ensure non-negative IAT
        current_time += iat_micros / 1_000_000.0

        # Toggle direction for bidirectional flows (simple alternation for now)
        if "bidirectional" in flow_type:
             is_forward = not is_forward

    return packets

def generate_pcap_file(filename, num_flows, packets_per_flow_range, flow_iat_mean_millis=10, flow_types=["tcp_short", "udp_long", "tcp_bidirectional"]):
    """Generates a pcap file with multiple flows."""
    all_packets = []
    current_global_time = time.time() # Start time for the pcap

    for i in range(num_flows):
        flow_type = random.choice(flow_types)
        num_packets = random.randint(packets_per_flow_range[0], packets_per_flow_range[1])

        # Simulate time between flows in milliseconds, convert to seconds
        time_between_flows_millis = max(0, int(random.gauss(flow_iat_mean_millis, flow_iat_mean_millis/2)))
        current_global_time += time_between_flows_millis / 1000.0

        # Generate packets for the flow, starting from the current_global_time
        flow_packets = generate_flow(
            flow_type=flow_type,
            num_packets=num_packets,
            start_time=current_global_time,
            iat_mean_micros=random.randint(500, 5000), # Random IAT within the flow
            payload_size_mean=random.randint(30, 500), # Random payload size
            # Include flags unless it's specifically a basic type where we want minimal headers
            include_flags=not (flow_type.startswith("tcp_short") or flow_type.startswith("udp_"))
        )
        all_packets.extend(flow_packets)
        print(f"Generated {len(flow_packets)} packets for flow {i+1}/{num_flows} ({flow_type})")

        # Update global time to the end time of the last packet in this flow
        if flow_packets:
             current_global_time = flow_packets[-1].time

    # Shuffle packets to simulate real-world interleaving of flows
    random.shuffle(all_packets)

    filepath = os.path.join(OUTPUT_DIR, filename)
    wrpcap(filepath, all_packets)
    print(f"Generated {len(all_packets)} packets in {filepath}")

# --- Generate Sample PCAP Files ---

# Example 1: Basic mixed traffic
generate_pcap_file(
    "mixed_traffic.pcap",
    num_flows=50,
    packets_per_flow_range=(5, 50),
    flow_iat_mean_millis=50,
    flow_types=["tcp_short", "udp_long", "tcp_bidirectional", "udp_bidirectional"]
)

# Example 2: Traffic with FIN and RST terminations
generate_pcap_file(
    "terminated_flows.pcap",
    num_flows=30,
    packets_per_flow_range=(5, 30),
    flow_iat_mean_millis=100,
    flow_types=["tcp_fin_terminate", "tcp_rst_terminate", "tcp_bidirectional"]
)

# Example 3: Longer flows to test active/idle times
generate_pcap_file(
    "long_flows_with_idle.pcap",
    num_flows=20,
    packets_per_flow_range=(50, 200), # More packets per flow
    flow_iat_mean_millis=200,
    flow_types=["tcp_bidirectional", "udp_long"]
)

# Example 4: Traffic with potential bulk characteristics (more packets with payload close together)
# This requires more careful IAT control and payload size consistency.
# Simplified simulation: bursts of packets with smaller IAT.
def generate_bulk_flow(num_packets=100, ip_version="ipv4", start_time=None):
    packets = []
    if start_time is None:
        start_time = time.time()

    current_time = start_time
    flow_src_ip = random.choice(SRC_IPS_V4) if ip_version == "ipv4" else random.choice(SRC_IPS_V6)
    flow_dst_ip = random.choice(DST_IPS_V4) if ip_version == "ipv4" else random.choice(DST_IPS_V6)
    flow_src_port = random.randint(MIN_PORT, MAX_PORT)
    flow_dst_port = random.choice([HTTP_PORT, HTTPS_PORT])

    tcp_seq = random.randint(0, 2**32 - 1)
    tcp_ack = random.randint(0, 2**32 - 1)

    # Simulate a handshake
    packets.append(IP(src=flow_src_ip, dst=flow_dst_ip)/TCP(sport=flow_src_port, dport=flow_dst_port, flags="S", seq=tcp_seq, window=random.randint(1024, 65535), options=[('MSS', 1460)]))
    packets[-1].time = current_time
    current_time += random.uniform(0.01, 0.05) # Small delay for SYN-ACK

    packets.append(IP(src=flow_dst_ip, dst=flow_src_ip)/TCP(sport=flow_dst_port, dport=flow_src_port, flags="SA", seq=tcp_ack, ack=tcp_seq + 1, window=random.randint(1024, 65535), options=[('MSS', 1460)]))
    packets[-1].time = current_time
    current_time += random.uniform(0.01, 0.05) # Small delay for final ACK

    packets.append(IP(src=flow_src_ip, dst=flow_dst_ip)/TCP(sport=flow_src_port, dport=flow_dst_port, flags="A", seq=tcp_seq + 1, ack=tcp_ack + 1, window=random.randint(1024, 65535)))
    packets[-1].time = current_time
    current_time += random.uniform(0.1, 0.5) # Delay before data transfer


    # Simulate bursts of data packets (potential bulk)
    payload_size = 500 # Consistent payload size for bulk simulation
    packets_in_burst = 10
    burst_interval_micros = 50 # Small IAT within a burst

    for _ in range(num_packets // packets_in_burst): # Generate several bursts
        for i in range(packets_in_burst):
            # Forward data packet
            tcp_ack = tcp_seq + payload_size
            packet = IP(src=flow_src_ip, dst=flow_dst_ip)/TCP(sport=flow_src_port, dport=flow_dst_port, flags="PA", seq=tcp_seq, ack=tcp_ack, window=random.randint(1024, 65535))/Raw(load='\x00' * payload_size)
            packet.time = current_time
            packets.append(packet)
            tcp_seq += payload_size
            current_time += burst_interval_micros / 1_000_000.0 # Small delay within burst

            # Simulate a backward ACK for the data packet
            ack_packet = IP(src=flow_dst_ip, dst=flow_src_ip)/TCP(sport=flow_dst_port, dport=flow_src_port, flags="A", seq=tcp_ack, ack=tcp_seq, window=random.randint(1024, 65535))
            ack_packet.time = current_time + random.uniform(0.001, 0.005) # Small delay after data packet
            packets.append(ack_packet)


        current_time += random.uniform(0.5, 2.0) # Longer delay between bursts (potential idle time or subflow boundary)

    # Simulate termination
    current_time += random.uniform(0.1, 0.5)
    packets.append(IP(src=flow_src_ip, dst=flow_dst_ip)/TCP(sport=flow_src_port, dport=flow_dst_port, flags="FA", seq=tcp_seq, ack=tcp_ack, window=random.randint(1024, 65535)))
    packets[-1].time = current_time
    current_time += random.uniform(0.01, 0.05)
    packets.append(IP(src=flow_dst_ip, dst=flow_src_ip)/TCP(sport=flow_dst_port, dport=flow_src_port, flags="A", seq=tcp_ack, ack=tcp_seq + 1, window=random.randint(1024, 65535)))
    packets[-1].time = current_time


    # Sort packets by time before returning
    packets.sort(key=lambda pkt: pkt.time)
    return packets

def generate_pcap_bulk(filename, num_flows=10, packets_per_flow=100):
    """Generates a pcap file specifically designed to create flows with bulk characteristics."""
    all_packets = []
    current_global_time = time.time()

    for i in range(num_flows):
        # Simulate time between flows
        time_between_flows_millis = random.randint(50, 500)
        current_global_time += time_between_flows_millis / 1000.0

        # Generate a bulk flow
        flow_packets = generate_bulk_flow(num_packets=packets_per_flow, start_time=current_global_time)
        all_packets.extend(flow_packets)
        print(f"Generated {len(flow_packets)} packets for bulk flow {i+1}/{num_flows}")

        # Update global time to the end time of the last packet in this flow
        if flow_packets:
             current_global_time = flow_packets[-1].time

    # No need to shuffle heavily, as bulk/subflow timing is sequential within a flow
    # Still good practice to sort by time before writing
    all_packets.sort(key=lambda pkt: pkt.time)

    filepath = os.path.join(OUTPUT_DIR, filename)
    wrpcap(filepath, all_packets)
    print(f"Generated {len(all_packets)} packets in {filepath}")

# Example 5: Traffic with potential bulk/subflow characteristics
generate_pcap_bulk("bulk_subflow_traffic.pcap", num_flows=15, packets_per_flow=150)


print(f"\nSample pcap files generated in the '{OUTPUT_DIR}' directory.")
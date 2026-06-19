from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

tcp_count = 0
udp_count = 0
icmp_count = 0

def process_packet(packet):

    global tcp_count
    global udp_count
    global icmp_count

    if IP in packet:

        src = packet[IP].src
        packet_length = len(packet)
        dst = packet[IP].dst

        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
            tcp_count += 1

        elif UDP in packet:
            protocol = "UDP"
            udp_count += 1

        elif ICMP in packet:
            protocol = "ICMP"
            icmp_count += 1

        print("\n===== Packet Captured =====")
        print(f"Source IP: {src}")
        print(f"Destination IP: {dst}")
        print(f"Protocol: {protocol}")
        print(f"Packet Length: {packet_length} bytes")

        print("\nStatistics")
        print(f"TCP Packets: {tcp_count}")
        print(f"UDP Packets: {udp_count}")
        print(f"ICMP Packets: {icmp_count}")

print("Starting Packet Sniffer...")
sniff(prn=process_packet, store=False)


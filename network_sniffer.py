from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.packet import Raw

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = ip_layer.proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

        print("\n New Packet Captured:")
        print(f" Source IP      : {ip_layer.src}")
        print(f" Destination IP : {ip_layer.dst}")
        print(f" Protocol       : {proto_name}")

        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f" Payload        : {payload[:64]}")
            except:
                print(f" Payload        : [unreadable]")

print("🟢 Starting Network Sniffer... Press CTRL+C to stop.\n")
sniff(prn=process_packet, store=False)


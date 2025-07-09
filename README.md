#  Basic Network Sniffer in Python

##  Project Overview

This project is a basic network packet sniffer built using Python. It captures real-time network traffic and displays essential packet details such as:

- Source IP Address  
- Destination IP Address  
- Protocol Type  
- Packet Payload (Raw Data)

This tool helps beginners understand how data flows through a network and provides insights into the structure of common networking protocols.

---

##  Objectives

- Capture live network packets using Python.
- Analyze packet headers and payloads.
- Understand IP, TCP, UDP, and ICMP protocol structures.
- Display key details like source/destination IP, protocol, and raw payload.
- Learn basics of network monitoring and ethical packet sniffing.

---

## 🛠 Tools & Libraries Used

| Tool       | Purpose                    |
|------------|----------------------------|
| Python 3.x | Programming Language       |
| socket     | Capturing packets          |
| struct     | Parsing binary data        |
| platform   | OS detection               |
| scapy (opt)| Advanced packet inspection |

##  How It Works

The program uses **raw sockets** to intercept packets directly from the network interface. It then decodes the IP header and protocol details using the `struct` module and displays them in a readable format.

##Code
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

Output:
<img width="459" alt="image" src="https://github.com/user-attachments/assets/bbeb8849-4378-48d5-9697-a7b8edc02b83" />



    
            

            

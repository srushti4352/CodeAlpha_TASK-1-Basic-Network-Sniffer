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

<img width="521" alt="image" src="https://github.com/user-attachments/assets/434f572f-3755-4096-b6b7-b682f12359eb" />




           
Output:


<img width="459" alt="image" src="https://github.com/user-attachments/assets/bbeb8849-4378-48d5-9697-a7b8edc02b83" />



    
            

            

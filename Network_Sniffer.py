from scapy.all import *

def packet_callback(packet):
    
    if packet.haslayer(IP):
        print("\n=== Nouveau Packet ===")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)
        print("Protocol:", packet[IP].proto)

        # TCP__
        if packet.haslayer(TCP):
            print("Protocol Type: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        # UDP__
        elif packet.haslayer(UDP):
            print("Protocol Type: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        # ICMP__
        elif packet.haslayer(ICMP):
            print("Protocol Type: ICMP")

        print("-" * 40)

print("Starting Network Sniffer...")
sniff(prn=packet_callback, store=False)

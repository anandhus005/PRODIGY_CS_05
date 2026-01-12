from scapy.all import sniff, IP, TCP, UDP

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        protocol_name = "OTHER"
        if TCP in packet:
            protocol_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            protocol_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            sport = "-"
            dport = "-"

        print(f"\n📌 Packet Captured:")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol_name}")
        print(f"Source Port    : {sport}")
        print(f"Destination Port: {dport}")

        # payload preview (safe)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            print(f"Payload size   : {len(payload)} bytes")


print("=== NETWORK PACKET ANALYZER ===")
print("Press CTRL+C to stop.\n")

sniff(prn=analyze_packet, store=False)

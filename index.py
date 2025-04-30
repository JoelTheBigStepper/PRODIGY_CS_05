from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("="*50)
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"📡 IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"🔀 Protocol: {ip_layer.proto}")

        if TCP in packet:
            print("🔓 TCP Segment")
            print(f"Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print("📨 UDP Datagram")
            print(f"Port: {packet[UDP].sport} -> {packet[UDP].dport}")

        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"📦 Payload:\n{payload.decode('utf-8', errors='replace')}")
            except:
                print("📦 Payload (binary):", payload)

def main():
    print("Starting packet sniffer... Press CTRL+C to stop.")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()

import scapy.all as scapy

def sniff_packets(interface, count):
    print(f"\n[*] Sniffing {count} packets on interface {interface}...\n")
    scapy.sniff(iface=interface, count=count, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
            payload = str(packet[scapy.TCP].payload)
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
            payload = str(packet[scapy.UDP].payload)
        else:
            payload = None

        print(f"Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol}")

        if payload:
            print("Payload:")
            print(payload)

interface = "eth0"  # Change this to your network interface
packet_count = 10    # Number of packets to sniff

sniff_packets(interface, packet_count)

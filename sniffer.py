'Task 5: Develop a packet sniffer tool that captures and analyzes network packets.'
'Display relevant information such as source and destination IP addresses,'
'protocols, and payload data.'

import scapy.all as scapy

def packet_sniffer(interface="Wi-Fi"):
    print(f"Sniffing started on interface {interface}")

    
    def packet_callback(packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            print(f"\nIP Packet: {src_ip} --> {dst_ip} Protocol: {protocol}")

            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load[:20]
                print(f"Payload: {payload.hex()}")

    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n User interrupted. Exiting...")


packet_sniffer()
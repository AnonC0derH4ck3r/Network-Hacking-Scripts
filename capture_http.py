#!/usr/bin/env python3
'''
@auth: Huzefa Dayanji
@role: Ethical Hacker
@lang: Python3
@desc: Sniff HTTP packets
@date: 01/01/2025
@size: 1,758 KB
'''
import scapy.all as scapy
import re

# Define the HTTP methods and port (80 for HTTP traffic)
HTTP_METHODS = ["GET", "POST"]
HTTP_PORT = 80

# Function to process captured HTTP packets
def process_http_packet(packet):
    # Check if the packet has IP and TCP layers
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        tcp_sport = packet[scapy.TCP].sport
        tcp_dport = packet[scapy.TCP].dport

        # Check if the packet is HTTP traffic (Port 80 for HTTP)
        if tcp_dport == HTTP_PORT or tcp_sport == HTTP_PORT:
            # If the packet contains raw data (i.e., HTTP payload)
            if packet.haslayer(scapy.Raw):
                raw_data = packet[scapy.Raw].load.decode(errors="ignore")

                # Filter for GET and POST requests (case-insensitive)
                if re.match(r"^(GET|POST)\s", raw_data, re.IGNORECASE):
                    print(f"--- HTTP Request ---")
                    print(f"Source IP: {ip_src}")
                    print(f"Destination IP: {ip_dst}")
                    print(f"Raw HTTP Data: {raw_data}")  # Display the first 300 characters of HTTP data
                    print("\n")

# Function to start sniffing packets
def sniff_packets(interface):
    print(f"Sniffing HTTP traffic on interface {interface}...")
    scapy.sniff(iface=interface, filter="tcp", prn=process_http_packet)

# Main function
if __name__ == "__main__":
    interface = "wlan0"  # Change this to the interface you're using (e.g., wlan0, eth0)
    sniff_packets(interface)

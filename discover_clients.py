#!/usr/bin/env python3
'''
@auth: Huzefa Dayanji
@role: Ethical Hacker
@lang: Python3
@desc: List devices connected to an Access Point
@date: 15/01/2025
@size: 3,919 KB
'''
import os
import random
import signal
import sys
from scapy.all import *
from prettytable import PrettyTable

# Dictionary to store stations and their details
stations = {}

# Flag to control the main loop
running = True

# Function to handle `CTRL+C`
def signal_handler(sig, frame):
    global running
    print("\nCTRL+C detected. Stopping sniffing and exiting...")
    running = False

# Set up the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Prompt user for BSSID of the Access Point (AP)
try:
    target_bssid = input("Enter the BSSID of the Access Point to monitor: ").strip()
except KeyboardInterrupt:
    print("\nExiting...")
    sys.exit(0)

# Function to change the channel randomly
def change_channel():
    channels = [2, 3, 4, 5, 6, 7, 8, 9, 10, 13]
    channel = random.choice(channels)
    os.system(f"sudo iw dev wlan0 set channel {channel}")

# Function to process packets
def packet_handler(packet):
    global stations
    if packet.haslayer(Dot11):
        # Extract the BSSID (AP's MAC address)
        bssid = packet[Dot11].addr2
        if bssid and bssid.lower() == target_bssid.lower():
            # Extract the client MAC address
            if packet.type == 2:  # Type 2 = Data frame
                client_mac = packet[Dot11].addr1
                signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None
                hostname = None

                # Check for hostname in specific layers (e.g., DHCP, mDNS, or NetBIOS)
                if packet.haslayer(DHCP):
                    hostname = packet[DHCP].options.get('hostname', None)
                elif packet.haslayer(DNSRR) and packet[DNSRR].rrname:
                    hostname = packet[DNSRR].rrname.decode('utf-8').rstrip('.')
                elif packet.haslayer(NBTSession) and hasattr(packet[NBTSession], 'NBT'):
                    hostname = packet[NBTSession].NBT.Names

                if client_mac not in stations:
                    stations[client_mac] = {
                        'signal_strength': [signal_strength],
                        'hostname': hostname,
                        'lost': 0,  # Placeholder for lost frames
                        'frames': 0,  # Placeholder for total frames
                        'rate': 'N/A',  # Placeholder for rate
                        'probes': []  # Placeholder for probes
                    }
                else:
                    stations[client_mac]['signal_strength'].append(signal_strength)
                    if hostname:
                        stations[client_mac]['hostname'] = hostname

# Function to display the table
def display_table():
    table = PrettyTable()
    table.field_names = ["BSSID", "STATION", "HOSTNAME", "PWR", "Rate", "Lost", "Frames", "Probes"]

    for station_mac, details in stations.items():
        valid_signals = [s for s in details['signal_strength'] if s is not None]
        avg_signal = (
            sum(valid_signals) / len(valid_signals)
        ) if valid_signals else "N/A"

        table.add_row([
            target_bssid.upper(),
            station_mac.upper(),
            details['hostname'] if details['hostname'] else "N/A",
            f"{avg_signal:.2f}" if avg_signal != "N/A" else "N/A",
            details['rate'],
            details['lost'],
            details['frames'],
            ", ".join(details['probes'])
        ])
    print(table)

# Main function to start sniffing
def main():
    global running
    try:
        while running:
            change_channel()
            sniff(iface="wlan0", prn=packet_handler, store=0, timeout=0.5)
            os.system('clear' if os.name == 'posix' else 'cls')
            display_table()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Exiting gracefully...")

# Run the main function
if __name__ == "__main__":
    main()

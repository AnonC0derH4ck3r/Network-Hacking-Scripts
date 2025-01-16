#!/usr/bin/env python3
'''
@auth: Huzefa Dayanji
@role: Ethical Hacker
@lang: Python3
@desc: Discover nearby Access Points
@date: 15/01/2025
@size: 4,301 KB
'''
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import os
import time
import threading
import random

# dictionary which will store the networks
networks = {}
# Set to track already-seen (BSSID, Channel) pairs
seen_networks = set()
channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]  # 2.4 GHz channels
current_channel = 1

# Track newly discovered networks with a timestamp
new_discovered_bssids = {}


def clear_screen():
    """
    Clears the terminal screen.
    """
    os.system("clear" if os.name == "posix" else "cls")


def channel_hopper(interface):
    """
    Change the channel of the interface randomly.
    """
    global current_channel
    while True:
        # Randomly choose a channel from the available list
        channel = random.choice(channels)
        os.system(f"iw dev {interface} set channel {channel}")
        current_channel = channel
        time.sleep(0.5)


def parse_packet(packet):
    """
    Process each packet to extract network information.
    """
    global new_discovered_bssids

    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode(errors="ignore") if packet[Dot11Elt].info else "Hidden SSID"
        dbm_signal = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else "N/A"

        # Extract channel from Dot11Elt
        channel = None
        for elt in packet[Dot11Elt]:
            if elt.ID == 3:
                channel = ord(elt.info)
                break

        # Fallback: Use the current channel
        if not channel:
            channel = current_channel

        # Check for duplicates
        if (bssid, channel) in seen_networks:
            return

        # Add new network to the set and dictionary
        seen_networks.add((bssid, channel))
        if bssid not in networks:
            networks[bssid] = {
                "SSID": ssid if ssid.strip() else "Unknown",
                "PWR": dbm_signal,
                "Beacons": 1,
                "Channel": channel,
            }
            # Mark as newly discovered with a timestamp
            new_discovered_bssids[bssid] = time.time()
        else:
            networks[bssid]["Beacons"] += 1


def display_networks():
    """
    Refresh and display the top 10 networks, highlighting newly discovered ones.
    """
    global new_discovered_bssids

    while True:
        clear_screen()
        print("\nScanning for Wi-Fi networks (Press CTRL+C to stop)...\n")
        print("{:<20} {:<5} {:<10} {:<5} {:<10}".format("BSSID", "PWR", "Beacons", "CH", "SSID"))
        print("-" * 60)

        # Sort networks by signal strength (PWR) and display the top 10
        sorted_networks = sorted(networks.items(), key=lambda x: x[1]["PWR"] if x[1]["PWR"] != "N/A" else -100, reverse=True)

        # Display networks for 10 seconds, highlight new ones
        for i, (bssid, info) in enumerate(sorted_networks[:25]):
            is_new = ""
            if bssid in new_discovered_bssids:
                time_since_discovery = time.time() - new_discovered_bssids[bssid]
                if time_since_discovery <= 10:  # Highlight as "NEW!" for 10 seconds
                    is_new = " (NEW!)"

            print("{:<20} {:<5} {:<10} {:<5} {:<10}{}".format(
                bssid.upper(), info["PWR"], info["Beacons"], info["Channel"], info["SSID"], is_new
            ))

        # Keep newly discovered WiFi networks with the "NEW!" label for up to 10 seconds
        new_discovered_bssids = {bssid: timestamp for bssid, timestamp in new_discovered_bssids.items() if time.time() - timestamp <= 10}

        time.sleep(1)


def main():
    interface = input("Enter your Wi-Fi interface (in monitor mode): ").strip()

    # Start channel hopper in a separate thread for random channel hopping
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface,), daemon=True)
    hopper_thread.start()

    # Start the display thread
    display_thread = threading.Thread(target=display_networks, daemon=True)
    display_thread.start()

    try:
        sniff(iface=interface, prn=parse_packet)
    except KeyboardInterrupt:
        print("\nScan stopped by user. Goodbye!")


if __name__ == "__main__":
    main()

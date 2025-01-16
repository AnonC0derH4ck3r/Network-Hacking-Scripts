# Network Hacking Scripts

This repository contains various scripts which is used in network hacking for educational and ethical purposes only. These scripts are designed to help you understand network security concepts and improve your skills in ethical hacking.

## Table of Contents
- [Scripts Overview](#scripts-overview)
  - [arp_poison.py](#arp_poisonpy)
  - [capture_http.py](#capture_httppy)
  - [de_auth.py](#de_authpy)
  - [show_ap.py](#show_appy)
  - [display_clients.py](#display_clientspy)
- [Usage Instructions](#usage-instructions)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)

## Scripts Overview

### 1. **arp_poison.py**
   - **Description**: This script performs an ARP poisoning attack, redirecting traffic between two devices on a local network.
   - **Usage**: Use it to simulate a Man-in-the-Middle (MITM) attack to intercept or manipulate traffic.
   - **Dependencies**: Requires Python and [scapy](https://scapy.readthedocs.io/).

### 2. **capture_http.py**
   - **Description**: Captures HTTP packets during a MITM attack, allowing you to analyze or log unencrypted web traffic.
   - **Usage**: Run it after performing an ARP poisoning attack to capture HTTP requests and responses.
   - **Dependencies**: Requires Python and [scapy](https://scapy.readthedocs.io/).

### 3. **de_auth.py**
   - **Description**: This script sends deauthentication packets to disconnect clients from a Wi-Fi network.
   - **Usage**: Use it to test Wi-Fi security or simulate a denial-of-service attack.
   - **Dependencies**: Requires [aircrack-ng](https://www.aircrack-ng.org/) and a compatible Wi-Fi adapter.

### 4. **show_ap.py**
   - **Description**: Discovers and displays nearby access points, showing information like SSID, BSSID, and signal strength.
   - **Usage**: Useful for scanning and mapping Wi-Fi networks in the area.
   - **Dependencies**: Requires Python and [scapy](https://scapy.readthedocs.io/).

### 5. **display_clients.py**
   - **Description**: Identifies and displays clients connected to a specific access point.
   - **Usage**: Useful for monitoring devices on your network or detecting unauthorized clients.
   - **Dependencies**: Requires Python and [scapy](https://scapy.readthedocs.io/).

## Usage Instructions

1. **Clone the repository**:
   git clone https://github.com/AnonC0derH4ck3r/Network-Hacking-Scripts.git.
   
2. **Change directory**
   cd Network-Hacking-Scripts
   
4. **Run the scripts**
   python de_auth.py


This `README.md` gives a clear overview of the scripts and their intended use, while also emphasizing the importance of ethical hacking and the legal responsibilities involved.

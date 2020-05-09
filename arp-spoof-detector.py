#!usr/bin/env python

import scapy.all as scapy
import tkinter as tk
from tkinter import messagebox
import argparse


# This function is to get Command Line input from user
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the interface to listen incoming packets")
    option = parser.parse_args()
    if not option.interface:
        parser.error("Please specify the interface")
    else:
        return option.interface


# This function gets the real mac from the given IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)  # Creates an ARP request packet for the given IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Creates broadcast packet
    arp_request_broadcast = broadcast / arp_request  # Merges the ARP packet and Broadcast packet
    # Sends the combine packet in the network and stores the answered list
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    mac = answered_list[0][1].hwsrc  # Gets only the MAC field from the answered list elements
    return mac  # returns the MAC address for the given IP


# This function sniffs all the incoming packet
def sniff_packets(inter):
    # interface , do not store in memory , and call back function "process_packet" for each sniff packet
    scapy.sniff(iface=inter, store=False, prn=process_packets)


# This function displays the Warning Pop-Up
def alert_box(message):
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning("Under Attack", "You are under arp attack by \n MAC ADDRESS: " + message)
    root.update()


# This function examines the incoming packet
def process_packets(packet):
    global t  # Accessing the global variable "t"
    global total_packet  # Accessing the global variable "total_packet"
    # The following IF statements check if the Packet is ARP packet and is it Response ARP packet
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            # From the packet, gets the IP stored in psrc field and pass the IP in get_mac function to get real mac
            real_mac = get_mac(packet[scapy.ARP].psrc)
            # From the packets, gets the mac stored in hswrc field
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:  # Compares the real_mac with packet_mac
                # If true
                if t == 1:  # To not flood up the desktop with popup
                    t = t + 1
                    # display the popup for two times by calling alert_box function
                    alert_box(packet[scapy.ARP].hwsrc)
                    alert_box(packet[scapy.ARP].hwsrc)

                # Prints the warning in terminal
                print("\r[-] You are under attack by " + packet[
                    scapy.ARP].hwsrc + ", Total Spoof packet received = " + str(total_packet), end="")
                total_packet = total_packet + 1  # Updates the packet count

        except IndexError or KeyboardInterrupt:
            pass


t = 1  # to check whether popups already displayed or not
total_packet = 1  # To count incoming ARP spoof packet
interface = get_arguments()  # calls the get_arguments function and stores the interface value
print("[+] Detecting Arp Attack \n")  # Displays that the program has been started
sniff_packets(interface)  # Calls the sniff_packet function and pass the interface value

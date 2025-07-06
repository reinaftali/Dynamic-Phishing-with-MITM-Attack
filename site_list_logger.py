import socket
import requests
import scapy.all as scapy
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1, srp1, sendp, srp, send
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
#from scapy.all import DNS, DNSQR, IP, sr1, srp1, UDP
import json
from selenium import webdriver
import re

import displaydns_parser

JSON_SITES = "sites.json"
JSON_LOG = "sites_log.txt"

#GECKO_DRIVER = r'C:\Users\reina\Downloads\DynamicPhishingProject\DynamicPhishingProject\geckodriver.exe'
#CHROME_DRIVER = r'C:\Users\reina\Downloads\DynamicPhishingProject\DynamicPhishingProject\chromedriver.exe'


def get_ips_nslookup(sites):
    """
       Performs a DNS lookup for each domain in the input dictionary and updates the values with their respective IP addresses.

       :param sites: Dictionary with keys as domain names and values as lists of IP addresses
       :return: Updated dictionary with values containing IP addresses obtained via nslookup
       """
    for i in sites:
        # print(i, sites[i])
        # if len(sites[i]) == 0:
        sites[i] = socket.gethostbyname_ex(i)[-1]  # nslookup
        print(socket.gethostbyname_ex(i)[-1])

    return sites


def get_ips_http_dns(sites):
    """
        Sends an HTTP request to each domain in the input dictionary, extracts the remote server IP, and performs a DNS query to Google's DNS server. Updates the values in the dictionary with the obtained IP addresses.

        :param sites: Dictionary with keys as domain names and values as lists of IP addresses
        :return: Updated dictionary with values containing IP addresses obtained via HTTP request and DNS query
        """
    for i in sites:
        print()

        resp = requests.get(f'http://www.{i}/', stream=True)  # http req
        if not resp.ok:
            continue

        try:
            print(resp.raw._connection.sock.getpeername()[0], end='\n\n')
            sites[i].append(resp.raw._connection.sock.getpeername()[0])
        except AttributeError as e:
            pass

        dns_req = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=i))  # dns req / query
        answer = sr1(dns_req, timeout=2, verbose=0)

        if answer is not None:
            for ans in range(answer[DNS].ancount):
                if answer[DNS]['DNS Resource Record'][ans].type == 1:
                    sites[i].append(answer[DNS]['DNS Resource Record'][ans].rdata)
                    print(answer[DNS]['DNS Resource Record'][ans].rdata)
                    print(answer[DNS]['DNS Resource Record'][ans].rdata == resp.raw._connection.sock.getpeername()[0])
                elif answer[DNS]['DNS Resource Record'][ans].type == 28:
                    sites[i].append(answer[DNS]['DNS Resource Record'][ans].rdata)
                    print(answer[DNS]['DNS Resource Record'][ans].rdata)
                    print(answer[DNS]['DNS Resource Record'][ans].rdata == resp.raw._connection.sock.getpeername()[0])

        print()

        sites[i] = list(set(sites[i]))

    return sites


def get_ips_dns_table(sites):
    """
      Opens a Chrome browser using Selenium to visit each domain in the input dictionary. Retrieves the DNS table and extracts the associated IP addresses. Updates the values in the dictionary with the obtained IP addresses.

      :param sites: Dictionary with keys as domain names and values as lists of IP addresses
      :return: Updated dictionary with values containing IP addresses obtained from DNS table
      """
    #driver = webdriver.Firefox(executable_path=r'C:\Users\reina\Downloads\DynamicPhishingProject\DynamicPhishingProject\geckodriver.exe')
    driver = webdriver.Chrome(executable_path=r'C:\Users\reina\Downloads\DynamicPhishingProject\DynamicPhishingProject\chromedriver.exe')
    for i in sites:
        driver.get('http://www.' + i)
        #driver.

        is_in_site = f"\w*\.*{i}"

        '''if i in dns_table:
            sites[i] += displaydns_parser.get_site_ip_from_dns_table(i)
            print(displaydns_parser.get_site_ip_from_dns_table(i))

        if 'www.' + i in dns_table:
            sites[i] += displaydns_parser.get_site_ip_from_dns_table('www.' + i)
            print(displaydns_parser.get_site_ip_from_dns_table('www.' + i))'''

        #print(is_in_site)
        dns_table = displaydns_parser.get_parsed_dns_table()
        for key in dns_table.keys():
            if re.search(is_in_site, key):
                sites[i] += displaydns_parser.get_site_ip_from_dns_table(key, dns_table)
                print(key, displaydns_parser.get_site_ip_from_dns_table(key, dns_table))
            #print(re.search(is_in_site, key))

        print()

        sites[i] = list(set(sites[i]))

    driver.close()

    return sites


def json_init():
    with open(JSON_SITES, 'r') as f:
        sites = json.loads(f.read())

    sites = get_ips_dns_table(get_ips_http_dns(get_ips_nslookup(sites)))

    with open(JSON_SITES, 'w') as f:
        f.write(json.dumps(sites))

    return sites


sites = json_init()


def is_addr_in_sites(ip, sites: dict):
    # print(socket.gethostbyaddr(ip)[0])
#    Searches for the input IP address in the values of the input dictionary. If found, returns the corresponding domain name (key).

    for i, j in zip(sites.keys(), sites.values()):
        # print(ip, j)
        for k in j:
            if ip == k:
                # print(ip, j)
                return i

    return -1


def log_sites(src_ip, site_ip):
    global sites

    site = is_addr_in_sites(site_ip, sites)

    if site != -1:
        with open(JSON_LOG, 'a') as f:
            f.write(f"{src_ip} -> {site}\n")


if __name__ == "__main__":
    pass

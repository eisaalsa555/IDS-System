# src/packet_sniffer.py
from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer('IP'):
        src = packet['IP'].src
        dst = packet['IP'].dst
        proto = packet.proto
        print(f"[+] Packet: {src} -> {dst} | Protocol: {proto}")

def start_sniffing():
    sniff(prn=packet_callback, store=False)

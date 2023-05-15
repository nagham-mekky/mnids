from scapy.all import *
import ipaddress
import sys
import os

def is_tcp_null(packet):
    return packet.haslayer(TCP) and packet[TCP].flags == 0x00

def is_tcp_stealth(packet1, packet2, packet3): #Change this
    if packet3.haslayer(TCP) == False:
        return False
    # If RST in packet 3
    if packet3[TCP].flags == 0x04:
        # Check packet2 and 1
        if packet2.haslayer(TCP) == False and packet1.haslayer(TCP) == False:
            return False
        # if packet 2 has SYN flag AND ACK and Packet1 has SYN flag
        if packet2[TCP].flags == 0x12 and packet1[TCP].flags == 0x02:
            return True
    return False
        

def is_tcp_fin(packet):
    return packet.haslayer(TCP) and packet[TCP].flags == 0x01

def is_tcp_xmas(packet):
    return packet.haslayer(TCP) and packet[TCP].flags == 0x29

def is_nikto(packet):
    return packet.haslayer(Raw) and packet[Raw].load.find(b'Nikto') != -1

def is_antarctica(packet):
    if packet.haslayer(IP) == False:
        return False

    # Antarctica ranges
    antarctica_ranges = [
        ipaddress.ip_network('31.187.93.0/26'),
        ipaddress.ip_network('46.136.153.0/24'),
        ipaddress.ip_network('46.136.176.0/24'),
        ipaddress.ip_network('46.136.231.0/24')
    ]

    for range in antarctica_ranges:
        if ipaddress.ip_address(packet[IP].src) in range:
            return True

    return False

def main():
    if len(sys.argv) < 2:
        print("Please provide a pcap file to read its packets")
        exit(0)

    fin_count = 0
    null_count = 0
    stealth_count = 0
    xmas_count = 0
    nikto_count = 0
    antarctica_count = 0

    if os.path.isfile(sys.argv[1]) == False:
        print(f"Error, provided file: {sys.argv[1]} is not a file")
        exit(0)

    packets = rdpcap(sys.argv[1])
    for i in range(len(packets) - 2):
        if is_tcp_stealth(packets[i], packets[i+1], packets[i + 2]):
            print(f"TCP Stealth packet recieved")
            stealth_count += 1

    for packet in packets:
        if is_tcp_null(packet):
            print(f"TCP NULL packet recieved")
            null_count += 1
        if is_tcp_fin(packet):
            print(f"TCP FIN packet recieved")
            fin_count += 1
        if is_tcp_xmas(packet):
            print(f"TCP XMAS packet recieved")
            xmas_count += 1
        if is_nikto(packet):
            print(f"Nikto Scanner packet recieved")
            nikto_count += 1
        if is_antarctica(packet):
            print(f"Antartica packet recieved")
            antarctica_count += 1

    print("Summary: ")
    print(f"TCP NULL packets: {null_count}")
    print(f"TCP STEALTH packets: {stealth_count}")
    print(f"TCP FIN packets: {fin_count}")
    print(f"TCP XMAS packets: {xmas_count}")
    print(f"Nikto Scanner packets: {nikto_count}")
    print(f"Antarctica packets: {antarctica_count}")

main()
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from colorama import Fore, Back, init
import os

init()

# Function to start
def start():
    print()
    print(Back.BLACK + Fore.YELLOW + "----------- PACKET SNIFFER -----------")
    print(Back.BLACK + Fore.YELLOW + "-----------NETWORK PACKET ANALYZER-----------")
    terms = Fore.GREEN + """
    START SNIFFING ??? (yes/no)
    """
    print(terms)

# Function to prompt the user to start
def can_start():
    start()
    choice = input().lower()
    return choice == "yes"

# Packet callback function
def packet_callback(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto

            log_data = Back.BLACK + Fore.RED + f"Source IP: {src_ip} --> Destination IP: {dst_ip} | Protocol: {proto}\n"

            if TCP in packet:
                payload = packet[TCP].payload
                log_data += Fore.RED + f"TCP Payload: {payload}\n"
            elif UDP in packet:
                payload = packet[UDP].payload
                log_data += Fore.CYAN + f"UDP Payload: {payload}\n"
            elif ICMP in packet:
                payload = packet[ICMP].payload
                log_data += Fore.BLUE + f"ICMP Payload: {payload}\n"

            with open("packet_log.txt", "a") as log_file:
                log_file.write(log_data)

            print("Packet logged.")
    except Exception as e:
        print(f"An error occurred while processing a packet: {e}")

if __name__ == "__main__":
    try:
        if can_start():
            print("Starting packet sniffing...")
            print(Back.WHITE + "Press Ctrl+C to stop.")
            sniff(prn=packet_callback, filter="ip")
        else:
            print("Exiting.")
    except KeyboardInterrupt:
        print("Packet sniffing interrupted by user. Exiting.")
    except Exception as e:
        print(f"An error occurred: {e}")

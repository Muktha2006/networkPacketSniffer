from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from colorama import init, Fore
import socket
import datetime

init(autoreset=True)

captured_packets = []

stats = {
    "TOTAL": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "DNS": 0,
    "HTTP": 0,
    "HTTPS": 0,
    "ARP": 0,
    "OTHER": 0
}


def service_name(port):
    common = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-ALT"
    }

    if port in common:
        return common[port]

    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"


def process_packet(packet):

    captured_packets.append(packet)
    stats["TOTAL"] += 1

    print(Fore.CYAN + "=" * 75)
    print(Fore.YELLOW + "PACKET #" + str(stats["TOTAL"]))
    print(Fore.CYAN + "=" * 75)

    print("Time :", datetime.datetime.now().strftime("%H:%M:%S"))

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        print(Fore.GREEN + f"Source IP      : {src}")
        print(Fore.GREEN + f"Destination IP : {dst}")

        if packet.haslayer(TCP):

            stats["TCP"] += 1

            sport = packet[TCP].sport
            dport = packet[TCP].dport

            print(Fore.MAGENTA + "Protocol       : TCP")
            print(f"Source Port    : {sport} ({service_name(sport)})")
            print(f"Dest Port      : {dport} ({service_name(dport)})")

            if sport == 80 or dport == 80:
                stats["HTTP"] += 1
                print(Fore.YELLOW + "HTTP Traffic Detected")

            if sport == 443 or dport == 443:
                stats["HTTPS"] += 1
                print(Fore.YELLOW + "HTTPS Traffic Detected")

        elif packet.haslayer(UDP):

            stats["UDP"] += 1

            sport = packet[UDP].sport
            dport = packet[UDP].dport

            print(Fore.BLUE + "Protocol       : UDP")
            print(f"Source Port    : {sport} ({service_name(sport)})")
            print(f"Dest Port      : {dport} ({service_name(dport)})")

        elif packet.haslayer(ICMP):

            stats["ICMP"] += 1

            print(Fore.RED + "Protocol       : ICMP")
            print("Type           :", packet[ICMP].type)
            print("Code           :", packet[ICMP].code)

        else:

            stats["OTHER"] += 1
            print("Protocol       : OTHER")

    elif packet.haslayer(ARP):

        stats["ARP"] += 1

        print(Fore.YELLOW + "Protocol       : ARP")
        print("Source MAC     :", packet[ARP].hwsrc)
        print("Destination MAC:", packet[ARP].hwdst)

    if packet.haslayer(DNS):

        stats["DNS"] += 1

        print(Fore.CYAN + "DNS Packet     : YES")

        if packet.haslayer(DNSQR):
            try:
                print("Domain         :", packet[DNSQR].qname.decode().rstrip("."))
            except:
                pass

    print(Fore.CYAN + "-" * 75)


print(Fore.GREEN + "=" * 75)
print(Fore.YELLOW + "ADVANCED NETWORK PACKET SNIFFER")
print(Fore.GREEN + "=" * 75)
print("Capturing all packets...")
print("Press CTRL+C to stop.\n")

try:

    sniff(
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:

    print("\nStopping Capture...")

    wrpcap("captured_packets.pcap", captured_packets)

    print(Fore.GREEN + "\nPackets saved to captured_packets.pcap\n")

    print(Fore.CYAN + "=" * 50)
    print(Fore.YELLOW + "CAPTURE SUMMARY")
    print(Fore.CYAN + "=" * 50)

    for key, value in stats.items():
        print(f"{key:10}: {value}")

    print(Fore.CYAN + "=" * 50)
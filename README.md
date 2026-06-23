# Network Packet Sniffer

## Project Description

This project is a Python-based Network Packet Sniffer developed using the Scapy library. It captures live network packets from the selected network interface and displays useful information such as source and destination IP addresses, protocol type, port numbers, and packet statistics. The application also saves captured packets in PCAP format for future analysis.

## Features

- Capture live network packets
- Display source and destination IP addresses
- Detect TCP, UDP, ICMP, ARP, HTTP, HTTPS, and DNS packets
- Display source and destination port numbers
- Save captured packets to a PCAP file
- Show packet statistics by protocol
- Color-coded terminal output for better readability

## Technologies Used

- Python 3.x
- Scapy
- Colorama

## Requirements

Install the required packages using:

```bash
pip install -r requirements.txt
```

## How to Run

1. Clone or download the project.
2. Open the project folder in VS Code.
3. Install the required packages:

```bash
pip install -r requirements.txt
```

4. Run the program:

```bash
python packet_sniffer.py
```

5. Run the terminal as Administrator if required for packet capturing.

## Project Structure

```
PacketSniffer/
│
├── packet_sniffer.py
├── README.md
├── requirements.txt
├── .gitignore
├── captures/
└── screenshots/
```

## Sample Output

The program displays:

- Source IP Address
- Destination IP Address
- Source Port
- Destination Port
- Protocol Type
- Packet Length
- Packet Statistics Summary

## Screenshots

Screenshots of the application output are available in the `screenshots` folder.

## Future Enhancements

- Graphical User Interface (GUI)
- Packet filtering by IP or protocol
- Export captured packets to CSV
- Real-time traffic visualization
- Email alerts for suspicious traffic

## Author

MUKTHA SREE T

BE-CSE(Cyber security)

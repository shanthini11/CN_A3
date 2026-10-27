# CN Assignment 3 - Mini Packet Analyzer

A small command-line packet analyzer for IPv4 packets. It captures raw frames with Scapy, converts them to bytes, and parses the IPv4, TCP and UDP headers manually in `parser.py`.

## Features
- Capture raw packets on a selected network interface.
- Number and timestamp parsed IPv4 packets.
- Show packet size and source/destination addresses and ports.
- Manually parse IPv4, TCP and UDP header fields.
- Filter by TCP/UDP, source/destination IP, and source/destination port.
- Inspect an individual packet's headers and payload in hex and text.
- Offline parser tests that do not require live capture.

## Important
Only capture traffic on a computer/network you own or are authorized to analyze. Scapy is used only to collect raw bytes; `parser.py` performs the header parsing itself.

This starter supports ordinary Ethernet frames carrying IPv4. Non-IPv4 frames are skipped. IPv6, VLAN-tagged Ethernet and later fragments of a fragmented IP packet are not fully decoded in this simple version.

## Setup (macOS/Linux)

Run these commands in the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python test_parser.py
python main.py
```

If packet capture fails because of permissions on macOS, try:

```bash
sudo .venv/bin/python main.py
```

Choose the interface connected to your network. On many Macs, Wi-Fi is `en0`, but use the list printed by the program. Start ordinary network activity during capture to help collect packets.

## Menu
1. Show all parsed IPv4 packets.
2. Filter by protocol, source/destination IP and/or source/destination port. Leave a field blank to skip it.
3. Inspect the full details for a packet number.
4. Exit.

## Files
- `main.py`: program flow and menu.
- `capture.py`: captures raw frames only.
- `parser.py`: manual byte-by-byte IPv4/TCP/UDP parsing.
- `display.py`: summary table and packet detail output.
- `filters.py`: packet filtering.
- `test_parser.py`: small synthetic TCP/UDP packet tests.
- `TEAM_TASKS.md`: suggested three-person split and GitHub workflow.

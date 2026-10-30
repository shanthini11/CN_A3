# CN Assignment 3 - Mini Packet Analyzer

A small command-line packet analyzer for IPv4 packets. It captures raw frames with Scapy, converts them to bytes, and parses the IPv4, TCP and UDP headers manually in `parser.py`.

## Features
- Capture raw packets on a selected network interface.
- Number and timestamp parsed IPv4 packets.
- Show packet size and source/destination addresses and ports.
- Manually parse IPv4, TCP and UDP header fields.
- Filter by TCP/UDP, source/destination IP, and source/destination port.
- Inspect an individual packet's headers and payload in hex and text.
- Offline parser, filter and display tests that do not require live capture.

## Important
Only capture traffic on a computer/network you own or are authorized to analyze. Scapy is used only to collect raw bytes; `parser.py` performs the header parsing itself.

This version supports Ethernet frames carrying IPv4, with or without a single 802.1Q VLAN tag. Non-IPv4 frames are skipped. IPv6, double-tagged Ethernet and later fragments of a fragmented IP packet are not fully decoded in this simple version.

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

## Setup (Windows)

1. Install [Npcap](https://npcap.com) (Scapy needs it to capture packets on Windows). Keep the default installer options.
2. Run these commands in PowerShell in the project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py test_parser.py
py test_filters.py
py test_display.py
py main.py
```

If PowerShell blocks `Activate.ps1`, use Command Prompt and run `.venv\Scripts\activate.bat` instead.

The program lists interfaces by number with their friendly names (for example `Wi-Fi`) and marks the default one; press Enter to use it. If capture fails with a permission error, open the terminal with **Run as administrator**.

## Tests

The tests use packet bytes built in the code, so they do not need live capture or administrator rights:

- `test_parser.py`: IPv4/TCP/UDP parsing, invalid and truncated packets, IPv4 options, UDP fragments, VLAN-tagged frames.
- `test_filters.py`: protocol, IP and port filters, combined filters, no matches, missing fields and invalid filter values.
- `test_display.py`: summary columns, detailed IP/TCP/UDP header fields, payload hex/text, empty payloads and missing values.

## Menu
1. Show all parsed IPv4 packets.
2. Filter by protocol, source/destination IP and/or source/destination port. Leave a field blank to skip it. Invalid values (for example a port above 65535 or a malformed IP) are reported and no filter is applied.
3. Inspect the full details for a packet number.
4. Exit.

## Files
- `main.py`: program flow and menu.
- `capture.py`: captures raw frames only.
- `parser.py`: manual byte-by-byte IPv4/TCP/UDP parsing.
- `display.py`: summary table and packet detail output.
- `filters.py`: packet filtering.
- `test_parser.py`, `test_filters.py`, `test_display.py`: offline tests (see Tests above).
- `DOCUMENTATION.md`: full project documentation, byte-level parsing explanation and test results.
- `Report A3.docx`: assignment report with test screenshots and each member's contribution.

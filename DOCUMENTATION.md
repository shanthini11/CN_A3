# CN Assignment 3 — Mini Packet Analyzer: Project Documentation

This document describes the group project as a whole: design, implementation, setup, testing, integration, and limitations. It records shared project outcomes and does not divide the work into individual member sections.

Repository: https://github.com/shanthini11/CN_A3

## Contents

1. [Overview](#1-overview)
2. [How the modules work together](#2-how-the-modules-work-together)
3. [Setup](#3-setup)
4. [Running the program](#4-running-the-program)
5. [How a packet is decoded from bytes](#5-how-a-packet-is-decoded-from-bytes)
6. [Testing](#6-testing)
7. [Limitations and privacy](#7-limitations-and-privacy)
8. [Group implementation and integration](#8-group-implementation-and-integration)

## 1. Overview

The Mini Packet Analyzer is a Python command-line application with functionality similar in spirit to Wireshark. It:

- captures packets sent or received by the host and numbers and timestamps them;
- shows packet size, addresses, ports, and protocol in a summary table;
- manually decodes IPv4, TCP, and UDP headers from raw bytes (Scapy is used to capture raw frames, not to decode the headers);
- filters packets by protocol (TCP/UDP), source/destination IP, and source/destination port;
- displays a selected packet's IP header, TCP/UDP header, and payload in hexadecimal and text form.

### Project files

| Area | Files | Purpose |
|---|---|---|
| Program flow and capture | `main.py`, `capture.py` | Collect capture settings, capture raw frames, and connect the program modules. |
| Packet parsing | `parser.py` | Decode raw Ethernet/IPv4/TCP/UDP bytes into packet dictionaries. |
| Filtering | `filters.py` | Apply protocol, address, and port filters. |
| Display | `display.py` | Print packet summaries and detailed packet views. |
| Automated tests | `test_parser.py`, `test_filters.py`, `test_display.py` | Verify parsing, filtering, and output formatting with offline test data. |
| Dependencies | `requirements.txt` | Lists Scapy, the project's packet-capture dependency. |

## 2. How the modules work together

```
main.py ──► capture.py ──► raw frame bytes + timestamp
   │
   ├──► parser.py   bytes ──► packet dictionary (or None if not IPv4)
   ├──► filters.py  list of packet dictionaries ──► matching packets
   └──► display.py  packet dictionaries ──► summary table / detailed view
```

1. `main.py` asks for the network interface, maximum packet count, and capture duration.
2. `capture.py` uses Scapy's `sniff()` to capture frames and records `bytes(packet)` with a timestamp.
3. `parser.py` converts each raw frame into a dictionary. Frames that are not supported IPv4 frames return `None` and are skipped.
4. The menu lets the user show all parsed packets, filter packets, inspect a packet by number, or exit.

The packet dictionary returned by `parse_packet()` is the shared format used by the modules:

```python
{
    "number": 17,
    "time": "14:32:08.421",
    "size": 106,  # captured frame size in bytes
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.20",
    "protocol": "TCP",  # TCP, UDP, ICMP, or OTHER
    "src_port": 49152,  # None if not TCP/UDP or header incomplete
    "dst_port": 8080,
    "ip": {
        "version", "header_length", "total_length", "ttl", "protocol_number",
        "protocol_name", "checksum", "source_ip", "destination_ip", "fragment_offset"
    },
    "transport": {...},  # TCP or UDP header fields, or None
    "payload": b"..."  # application data bytes
}
```

## 3. Setup

### Windows

1. Install Npcap with the default options; Scapy uses it to capture packets on Windows.
2. Open a terminal in the project folder and run:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   py -m pip install -r requirements.txt
   ```

   If PowerShell blocks `Activate.ps1`, use Command Prompt and run:

   ```bat
   .venv\Scripts\activate.bat
   py -m pip install -r requirements.txt
   ```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If capture fails due to permissions on macOS or Linux, try running the program with the appropriate capture permissions for the system. On Windows, check that Npcap is installed and consult the capture error hint if the adapter cannot be opened.

`requirements.txt` contains Scapy. The `.venv/` folder is excluded by `.gitignore` and should not be committed.

## 4. Running the program

From the activated virtual environment, run:

```powershell
py main.py
```

On macOS/Linux, use `python main.py` if that is the active Python interpreter.

1. **Interface:** The program lists interfaces by number with friendly names, descriptions, and IP addresses, and marks the default interface. Press Enter to select the default, or type an interface number or name. On Windows, the Wi-Fi adapter may appear as `Wi-Fi`; on many Macs it is `en0`.
2. **Capture limits:** Enter the maximum number of packets (default 50) and duration in seconds (default 15). Capture stops when either limit is reached. Generate ordinary network activity, such as opening a website, while capture is running.
3. **Menu:**
   - 1 — show all parsed IPv4 packets;
   - 2 — filter by protocol, source/destination IP, and/or source/destination port; leave a field blank to skip it;
   - 3 — inspect a packet by number;
   - 4 — exit.

Invalid filter values (for example, port `99999` or IP `192.168.1.300`) are reported and no filter is applied.

## 5. How a packet is decoded from bytes

All multi-byte fields are big-endian (network byte order) and are read with `int.from_bytes(data, "big")`. Offsets below are counted from the start of each header.

### Ethernet header — 14 bytes

Bytes 12–13 contain the EtherType. `0x0800` means IPv4; other EtherTypes are skipped. For an ordinary Ethernet frame, the IPv4 header starts at byte 14.

### Optional 802.1Q VLAN tag — 4 bytes

If the EtherType is `0x8100`, a VLAN tag is present. Bytes 14–15 contain the tag information and bytes 16–17 contain the real EtherType. The IPv4 header then starts at byte 18. The parser supports a single VLAN tag.

### IPv4 header — 20–60 bytes

| Bytes | Field | How it is extracted |
|---|---|---|
| 0 | Version, IHL | `version = byte >> 4`; `header_length = (byte & 0x0F) * 4` (IHL counts 4-byte words). |
| 2–3 | Total length | IPv4 header plus transport data; excludes Ethernet. |
| 6–7 | Flags and fragment offset | `fragment_offset = value & 0x1FFF`; More Fragments flag = `value & 0x2000`. |
| 8 | TTL | One byte. |
| 9 | Protocol | 6 = TCP, 17 = UDP, 1 = ICMP. |
| 10–11 | Header checksum | Displayed in hexadecimal. |
| 12–15 / 16–19 | Source / destination IP | Four bytes each, converted with `ipaddress.IPv4Address`. |

The transport header starts at `ip_start + header_length`, where `ip_start` is 14 or 18 when a VLAN tag is present. IPv4 data ends at `ip_start + total_length`; Ethernet padding is not counted as payload.

### TCP header — 20–60 bytes

| Bytes | Field | How it is extracted |
|---|---|---|
| 0–1 / 2–3 | Source / destination port | 16-bit integers. |
| 4–7 / 8–11 | Sequence / acknowledgment number | 32-bit integers. |
| 12 | Data offset | `header_length = (byte >> 4) * 4`; values below 20 are invalid. |
| 13 | Flags | FIN `0x01`, SYN `0x02`, RST `0x04`, PSH `0x08`, ACK `0x10`, URG `0x20`, ECE `0x40`, CWR `0x80`; for example, `0x18` = PSH + ACK. |
| 14–15 | Window size | 16-bit integer. |
| 16–17 | Checksum | Displayed in hexadecimal. |

TCP payload length is IP total length − IP header length − TCP header length.

### UDP header — 8 bytes

The source port is at bytes 0–1, destination port at 2–3, length at 4–5, and checksum at 6–7. UDP length includes the 8-byte UDP header, so payload length = UDP length − 8. A UDP length below 8 or greater than the IPv4 data length is rejected, except in the first fragment of a fragmented packet, which may contain only part of the UDP datagram.

### Payload display

Payload bytes are shown 16 per line as hexadecimal, with the same bytes shown as text alongside. Printable ASCII bytes (`0x20`–`0x7E`) appear as characters; other bytes appear as `.` because payloads may be binary or encrypted. A packet without application data shows a payload length of 0 and `Empty payload.`

## 6. Testing

### Offline tests

These tests construct packet bytes in code and do not need live capture or administrator rights. Run:

```powershell
py test_parser.py
py test_filters.py
py test_display.py
```

| File | Tests | Coverage |
|---|---|---|
| `test_parser.py` | 10 | TCP and UDP parsing, short/non-IPv4 frames, truncated IPv4 header, IPv4 options, invalid TCP header length, invalid UDP lengths, UDP fragments, and VLAN-tagged frames. |
| `test_filters.py` | 9 | Protocol, IP and port filters, combined filters, no matches, missing fields, invalid values, and filtering real `parse_packet()` output. |
| `test_display.py` | 8 | Summary columns, empty and incomplete summaries, TCP fields from the assignment sample, UDP fields, empty payload, missing header data, and unprintable payload bytes. |

The recorded offline-test output was:

```
All parser tests passed!
All filter tests passed!
All display tests passed!
```

### Live capture results

- **macOS / en0:** One capture collected 20 frames and displayed 8 IPv4/UDP packets. A 500-frame capture displayed 327 IPv4 packets including TCP. UDP, destination-port, and TCP filters worked, and TCP/UDP details were displayed.
- **Windows 11 / Wi-Fi:** An earlier 5-second capture collected 300 frames and parsed 163 IPv4 packets (97 TCP and 66 UDP). TCP and UDP filters returned packets of the selected protocol, and packet detail views were displayed without errors.
- **HTTP exchange:** While capturing, `curl.exe -4 http://example.com` was used to generate an HTTP request. After single-VLAN-tag support was added, the capture could display the SYN, SYN-ACK, ACK, GET request, HTTP response, and FIN packets in the exchange.
- **Latest recorded Windows capture:** With a limit of 50,000 frames and 60 seconds, capture stopped at 47,986 raw frames and parsed 20,897 IPv4 packets. The TCP destination-port 80 filter found packet #1642 (the 129-byte HTTP GET request); the TCP source-port 80 filter found packet #1644 (the HTTP response). UDP destination-port 53 filtering found DNS packets to 8.8.8.8. UDP destination port 443 returned no matches in that capture.

### Manual test results

The interactive checklist was run on Windows 11 using Wi-Fi (192.168.40.117). Results below reflect outputs observed during the manual runs and previously recorded tests. Capture-dependent cases are noted rather than treated as code failures when the required traffic was not present.

| # | Test | Result |
|---|---|---|
| 1 | Interface list shows friendly names and default | Pass. Available adapters were listed and Wi-Fi was marked as the default, with its adapter description and IPv4 address. |
| 2 | Capture known traffic (DNS lookup and HTTP request) | Pass. `curl.exe -4 http://example.com` returned HTML and DNS traffic to 8.8.8.8:53 was captured. A large capture collected 47,986 raw frames and parsed 20,897 IPv4 packets. |
| 3 | Summary table has the required columns | Pass in an earlier manual run. The table showed No., Time, Source IP, Src Port, Destination IP, Dst Port, Protocol, and Length, followed by the packet count and Length explanation. |
| 4 | TCP / UDP protocol filters | Pass. TCP and UDP filters returned packets of the selected protocol; lowercase protocol input was accepted. |
| 5 | Source / destination IP filters | Tested in earlier manual runs. Filters were exercised using the local Wi-Fi address (192.168.40.117) and other addresses. |
| 6 | Source / destination port filters and combined filter | Pass. TCP destination-port 80, TCP source-port 80, and combined filter cases returned matching traffic when present. |
| 7 | No-match filters and invalid values | Pass for observed cases. No-match filters displayed `No matching IPv4 packets to display.` Invalid filter and menu inputs produced validation messages. |
| 8 | Detailed TCP view with readable HTTP payload | Pass. Packet #1642 was 129 bytes, used destination port 80 and flags PSH, ACK, and showed `GET / HTTP/1.1` and `Host: example.com`. Lengths agreed: 20-byte IP header + 20-byte TCP header + 75-byte payload = 115-byte IP packet; 14-byte Ethernet header + 115 = 129-byte frame. |
| 9 | Detailed UDP view (DNS) and lengths | Pass with a Windows DNS-suffix note. Packet #1791 used destination port 53. UDP length was 50 bytes (8-byte header + 42-byte payload); IP total length was 70 bytes (20-byte IP header + 50-byte UDP datagram). The query included the Windows search suffix `iiitd.edu.in`, so the decoded name was `example.com.iiitd.edu.in`. |
| 10 | Packet with empty payload (TCP SYN) | Pass. Packet #1615 showed SYN, a 32-byte TCP header, and 0-byte payload. |
| 11 | Invalid menu input and invalid packet number | Pass. G1–G6 returned the expected messages for invalid option 7, blank input, nonnumeric packet number, missing packet number, negative packet number, and exit. Exit printed `Goodbye!` and returned to the command prompt. |

### Detailed packet-inspection cases from the assignment checklist

| Case | Result | Evidence / note |
|---|---|---|
| F1 — HTTP request | Pass | Packet #1642: frame length 129; destination port 80; PSH, ACK; 75-byte payload containing `GET / HTTP/1.1` and `Host: example.com`. |
| F2 — HTTP response | Pass with frame-layout difference | Packet #1644: frame length 985; source port 80; payload began `HTTP/1.1 200 OK` and included HTML. IP total length was 971 and TCP payload was 931 bytes. The frame was 14 bytes longer than the IP packet, rather than the checklist's 18-byte VLAN-tag example; this environment-specific difference alone does not indicate a parser failure. |
| F3 — SYN | Pass | Packet #1615: SYN, 0-byte payload, and 32-byte TCP header. |
| F4 — SYN-ACK | Pass | Packet #1640: flags SYN, ACK; acknowledgment number 1980295497 equals packet #1615's sequence number 1980295496 + 1. |
| F5 — DNS query | Pass with DNS-suffix difference | Packet #1791 used destination port 53 and had consistent UDP/IP lengths. Windows appended `iiitd.edu.in` to the query name. |
| F6 — HTTPS/TLS payload | Pass | Packet #2140 used destination port 443 and had a 1,412-byte payload beginning `17 03 03`; the payload appeared as opaque hexadecimal, consistent with encrypted TLS data. |
| F7 — UDP port 443 / QUIC | Not observed; allowed by checklist | The filter returned `No matching IPv4 packets to display.` The checklist notes that UDP/443 traffic may be absent, so no packet was available to inspect. |

### Menu error and exit cases from the assignment checklist

| Case | Result | Observed output |
|---|---|---|
| G1 — Invalid menu option 7 | Pass | `Please choose 1, 2, 3, or 4.` |
| G2 — Blank menu input | Pass | `Please choose 1, 2, 3, or 4.` |
| G3 — Packet number abc | Pass | `Please enter a whole number.` |
| G4 — Packet number 999999 | Pass | `Packet number not found.` |
| G5 — Packet number -1 | Pass | `Packet number not found.` |
| G6 — Exit option 4 | Pass | `Goodbye!`; the program returned to the command prompt. |

## 7. Limitations and privacy

- Only Ethernet frames carrying IPv4 are decoded, with or without a single 802.1Q VLAN tag. IPv6, double-tagged (QinQ) frames, and later IP fragments are not fully decoded.
- The Windows loopback interface does not use Ethernet framing, so its packets are skipped; use Wi-Fi or Ethernet for this analyzer.
- Protocol filtering supports TCP and UDP only, as specified by the assignment. Each IP or port filter matches one direction (source or destination).
- The summary Length column is the captured frame size, including the Ethernet header. IP total length appears in the detailed view.
- Checksums are displayed but not verified.
- The payload text column is ASCII-only; other text (for example, non-English UTF-8) may appear as `.`.
- Captures can include device names, local addresses, and other identifying data. Do not commit packet dumps or share full payloads publicly. Capture only traffic you own or are authorized to analyze.

## 8. Group implementation and integration

The project was developed and integrated as a group. The core areas—capture and program flow, byte-level packet parsing, filtering, display, automated tests, and documentation—work together through the shared packet dictionary described in Section 2. Changes were tested against the offline test suite and the interactive capture workflow.

### Packet parsing and validation

- Multi-byte fields are decoded manually using network byte order; Scapy is used only for packet capture.
- The parser validates IPv4 and transport-header lengths before reading fields, and rejects invalid UDP lengths.
- UDP fragments are handled so the first fragment may retain its UDP header even if the datagram length exceeds the data in that fragment; later fragments are not incorrectly decoded as new UDP headers.
- Single 802.1Q VLAN tags are supported by reading the actual EtherType and adjusting the IPv4 header offset. This was important for displaying both outgoing requests and some incoming responses on the tested Windows Wi-Fi network.

### Filtering and validation

`filter_packets(packets, protocol, source_ip, destination_ip, source_port, destination_port)` returns packets matching all provided filters. Blank filters are ignored.

| Filter | Accepted values | Notes |
|---|---|---|
| Protocol | TCP, UDP, or blank | Case-insensitive. |
| Source / destination IP | Valid IPv4 address | Validated using `ipaddress`; malformed addresses are rejected. |
| Source / destination port | Whole number from 0 to 65535 | Compared numerically, so `0053` matches port 53. |

Invalid values are reported with a clear validation message and no filter is applied. Missing packet fields are handled safely; a packet without a valid port does not match a port filter.

### Display and interface integration

- The summary includes packet number, time, source IP and port, destination IP and port, protocol, and captured frame length. It prints a packet count and explains the meaning of Length and `-` for missing ports.
- The detailed view shows the required IP and TCP/UDP fields, the fragment offset, and a payload dump with 16 hexadecimal bytes per line and a corresponding ASCII view.
- Incomplete transport headers and missing values are handled with informative output instead of causing the display to crash.
- Interface selection lists friendly names, descriptions, and IP addresses, marks the default interface, and accepts a number, name, or Enter for the default. Capture error messages include platform-specific hints such as checking Npcap on Windows.
- The automated display tests use the assignment sample values (ports 49152 to 8080, sequence number 105482, PSH, ACK flags, checksums `0x8A31` and `0x2F81`, and payload text beginning `HELLO SERVER`).

### Automated test coverage

The offline suite covers valid TCP/UDP parsing, short and non-IPv4 frames, truncated headers, IPv4 options, invalid TCP header lengths, invalid UDP lengths, fragments, VLAN-tagged frames, combinations of filters, missing fields, invalid inputs, summary columns, detailed transport fields, empty payloads, and non-printable payload bytes. The recorded output from the three test scripts is:

```
All parser tests passed!
All filter tests passed!
All display tests passed!
```

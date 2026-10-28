# CN Assignment 3 — Mini Packet Analyzer: Project Documentation

This document combines the work of all three group members. Sections 1–7 describe the project as a whole; sections 8–10 record each member's individual contribution.

**Repository:** https://github.com/shanthini11/CN_A3

## Contents

1. [Overview](#1-overview)
2. [How the modules work together](#2-how-the-modules-work-together)
3. [Setup](#3-setup)
4. [Running the program](#4-running-the-program)
5. [How a packet is decoded from bytes](#5-how-a-packet-is-decoded-from-bytes)
6. [Testing](#6-testing)
7. [Limitations and privacy](#7-limitations-and-privacy)
8. [Member 1 — Packet capture and main program](#8-member-1--packet-capture-and-main-program)
9. [Member 2 — Packet parsing and testing](#9-member-2--packet-parsing-and-testing)
10. [Member 3 — Display, filters and final integration](#10-member-3--display-filters-and-final-integration)

---

## 1. Overview

A command-line packet analyzer, similar in spirit to Wireshark, written in Python. It:

- captures packets sent or received by the host and numbers and timestamps them;
- shows each packet's size, addresses, ports and protocol in a summary table;
- decodes the **IPv4, TCP and UDP headers manually from raw bytes** (Scapy is used only to obtain the raw bytes, as the assignment allows);
- filters packets by protocol (TCP/UDP), source/destination IP and source/destination port;
- shows a selected packet's IP header, TCP/UDP header and payload in hex and text.

| Role | Member | Files |
|---|---|---|
| Capture and integration | Member 1 (shanthu) | `capture.py`, `main.py` |
| Header parsing | Member 2 (palak) | `parser.py`, `test_parser.py` |
| Display and filters, final integration | Member 3 (Manojna) | `display.py`, `filters.py`, `test_filters.py`, `test_display.py` |

## 2. How the modules work together

```
main.py ──► capture.py ──► raw frame bytes + timestamp
   │
   ├──► parser.py   bytes ──► packet dictionary (or None if not IPv4)
   ├──► filters.py  list of packet dictionaries ──► matching packets
   └──► display.py  packet dictionaries ──► summary table / detailed view
```

1. `main.py` asks for the interface, maximum packet count and capture duration.
2. `capture.py` captures raw frames with Scapy's `sniff()` and stores only `bytes(packet)` and a timestamp.
3. `parser.py` turns each raw frame into a dictionary. Non-IPv4 frames return `None` and are skipped.
4. The menu lets the user list all packets, filter them, or inspect one packet.

The packet dictionary returned by `parse_packet()` is the shared format used by every module:

```python
{
    "number": 17, "time": "14:32:08.421", "size": 106,       # size = captured frame bytes
    "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20",
    "protocol": "TCP",                                        # "TCP", "UDP", "ICMP" or "OTHER"
    "src_port": 49152, "dst_port": 8080,                      # None if not TCP/UDP or header incomplete
    "ip": {"version", "header_length", "total_length", "ttl", "protocol_number",
           "protocol_name", "checksum", "source_ip", "destination_ip", "fragment_offset"},
    "transport": {...} or None,                               # TCP or UDP header fields
    "payload": b"...",                                        # application data bytes
}
```

## 3. Setup

### Windows (PowerShell)

1. Install [Npcap](https://npcap.com) with the default options (Scapy needs it to capture on Windows).
2. In the project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

If PowerShell blocks `Activate.ps1`, use Command Prompt and run `.venv\Scripts\activate.bat`.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If capture fails because of permissions on macOS, run `sudo .venv/bin/python main.py`. (Member 1's Mac needed an extra virtual-environment workaround; see section 8.2.)

`requirements.txt` contains only Scapy. The `.venv/` folder is excluded by `.gitignore` and must not be committed.

## 4. Running the program

```powershell
py main.py          # macOS/Linux: python main.py
```

1. **Interface.** The program lists interfaces by number with friendly names, descriptions and IP addresses, and marks Scapy's default interface. Press Enter for the default, or type a number or name. On Windows the Wi-Fi adapter appears as `Wi-Fi`; on many Macs it is `en0`.
2. **Maximum packets** (default 50) and **duration in seconds** (default 15). Capture stops when either limit is reached. Generate ordinary network activity (for example, open a website) while it runs.
3. **Menu:**
   1. Show all parsed IPv4 packets.
   2. Filter by protocol, source/destination IP and/or source/destination port. Leave a field blank to skip it. Invalid values (such as port `99999` or IP `192.168.1.300`) are reported and no filter is applied.
   3. Inspect one packet by number.
   4. Exit.

Example detailed view (from the offline tests, matching the assignment's sample packet):

```
PACKET #17
Time: 14:32:08.421
Packet length: 100 bytes (captured frame)

IP HEADER
------------------------------
Version: 4
Header length: 20 bytes
Total length: 86 bytes
TTL: 64
Protocol: TCP (number 6)
Header checksum: 0x8A31
Source IP: 192.168.1.10
Destination IP: 192.168.1.20
Fragment offset: 0

TCP HEADER
------------------------------
Source port: 49152
Destination port: 8080
Sequence number: 105482
Acknowledgment number: 208713
Header length: 20 bytes
Flags: PSH, ACK
Window size: 65535
Checksum: 0x2F81
Payload length: 46 bytes

PAYLOAD
------------------------------
Payload length: 46 bytes
Offset  Hex                                              Text
0000    48 45 4C 4C 4F 20 53 45 52 56 45 52 2C 20 74 68  HELLO SERVER, th
0010    69 73 20 69 73 20 61 20 6C 6F 6E 67 65 72 20 70  is is a longer p
0020    61 79 6C 6F 61 64 20 00 01 1B 5B 33 31 6D        ayload ...[31m
```

## 5. How a packet is decoded from bytes

All multi-byte fields are **big-endian** (network byte order) and are read with `int.from_bytes(data, "big")`. Offsets below are counted from the start of each header.

**Ethernet header (14 bytes)** — bytes 12–13 are the EtherType. `0x0800` means IPv4; anything else is skipped. The IPv4 header therefore starts at byte 14 of the frame.

**802.1Q VLAN tag (optional, 4 bytes)** — if the EtherType is `0x8100`, a VLAN tag has been inserted: bytes 14–15 hold the VLAN ID and bytes 16–17 hold the real EtherType. The IPv4 header then starts at byte 18. On the Windows Wi-Fi network used for testing, most *incoming* frames carried this tag, so without this step the program missed packets received by the host (for example, the server's half of every TCP connection). In the tables below, offsets are relative to the start of each header, wherever it begins.

**IPv4 header (20–60 bytes)**

| Bytes | Field | How it is extracted |
|---|---|---|
| 0 | Version, IHL | `version = byte >> 4`; `header_length = (byte & 0x0F) * 4` (IHL counts 4-byte words) |
| 2–3 | Total length | IP header + data, excluding Ethernet |
| 6–7 | Flags, fragment offset | `fragment_offset = value & 0x1FFF`; More Fragments flag = `value & 0x2000` |
| 8 | TTL | single byte |
| 9 | Protocol | `6` = TCP, `17` = UDP, `1` = ICMP |
| 10–11 | Header checksum | shown in hex |
| 12–15 / 16–19 | Source / destination IP | 4 bytes each, converted with `ipaddress.IPv4Address` |

The transport header starts at `ip_start + header_length` (`ip_start` is 14, or 18 with a VLAN tag). The IP data ends at `ip_start + total_length`, so Ethernet padding is not counted as payload.

**TCP header (20–60 bytes)**

| Bytes | Field | How it is extracted |
|---|---|---|
| 0–1 / 2–3 | Source / destination port | 16-bit integers |
| 4–7 / 8–11 | Sequence / acknowledgment number | 32-bit integers |
| 12 | Data offset | `header_length = (byte >> 4) * 4`; values below 20 are invalid |
| 13 | Flags | each bit: FIN `0x01`, SYN `0x02`, RST `0x04`, PSH `0x08`, ACK `0x10`, URG `0x20`, ECE `0x40`, CWR `0x80` — e.g. `0x18` = PSH + ACK |
| 14–15 | Window size | 16-bit integer |
| 16–17 | Checksum | shown in hex |

TCP payload = IP data after the TCP header, so `payload length = IP total length − IP header length − TCP header length`.

**UDP header (8 bytes)** — ports at bytes 0–1 and 2–3, length at 4–5, checksum at 6–7. The UDP length includes the 8-byte header, so `payload length = UDP length − 8`. A UDP length below 8, or larger than the IP data (except in the first fragment of a fragmented packet), is rejected.

**Payload display.** Payload bytes are shown 16 per line as hex, with the same bytes as text alongside. Printable ASCII bytes (`0x20`–`0x7E`) appear as characters (`0x48` = `H`); all other bytes appear as `.`, because many payloads are binary or encrypted. A packet without application data shows a payload length of 0 and `Empty payload.`

## 6. Testing

### Offline tests

These build packet bytes in code, so they need no live capture or administrator rights:

```powershell
py test_parser.py
py test_filters.py
py test_display.py
```

| File | Tests | What is covered |
|---|---|---|
| `test_parser.py` | 10 | TCP and UDP parsing, short/non-IPv4 frames, truncated IPv4 header, IPv4 options, invalid TCP header length, invalid UDP lengths, UDP fragments, VLAN-tagged frames |
| `test_filters.py` | 9 | protocol, IP and port filters, combined filters, no match, missing fields, invalid values, filtering real `parse_packet()` output |
| `test_display.py` | 8 | summary columns, empty and incomplete summaries, all TCP fields from the assignment sample, UDP fields, empty payload, missing header data, unprintable payload bytes |

**Latest result** (Windows 11, Python 3.12.5, Scapy 2.8.0):

```
All parser tests passed!
All filter tests passed!
All display tests passed!
```

### Live capture results

- **Member 1 (macOS, `en0`):** 20 frames → 8 IPv4/UDP packets; 500 frames → 327 IPv4 packets including TCP. UDP, destination-port and TCP filters worked, and TCP and UDP details were displayed (section 8.4).
- **Member 3 (Windows 11, `Wi-Fi`):** a 5-second capture gave 300 frames → 163 IPv4 packets (97 TCP, 66 UDP). The TCP and UDP filters returned 97 and 66 packets, and every packet's detailed view was displayed without errors. No administrator rights were needed.
- **Member 3, HTTP request check:** while capturing, `curl.exe -4 http://example.com` was run. Before the VLAN fix only the laptop's outgoing packets appeared (SYN, the `GET` request, FIN); the server's replies were missing because they arrived VLAN-tagged. After the fix the full exchange appeared: `SYN` → `SYN, ACK` → `ACK`, `GET / HTTP/1.1` (75-byte payload), `HTTP/1.1 200 OK` (932-byte payload), then `FIN, ACK` from both sides.

### Manual test results

The step-by-step manual test was run on Windows using the interactive menu. Record results here:

| # | Test | Result |
|---|---|---|
| 1 | Interface list shows friendly names and default | |
| 2 | Capture with known traffic (DNS lookup and HTTP request) | |
| 3 | Summary table shows all required columns | |
| 4 | TCP / UDP protocol filters | |
| 5 | Source / destination IP filters | |
| 6 | Source / destination port filters and combined filter | |
| 7 | No-match filter and invalid filter values | |
| 8 | Detailed TCP view with readable HTTP payload | |
| 9 | Detailed UDP view (DNS) and lengths check | |
| 10 | Packet with empty payload (TCP SYN) | |
| 11 | Invalid menu input and invalid packet number | |

## 7. Limitations and privacy

- Only Ethernet frames carrying IPv4 are decoded (with or without a single 802.1Q VLAN tag). IPv6, double-tagged (QinQ) frames and later IP fragments are not fully decoded.
- The Windows loopback interface does not use Ethernet framing, so its packets are skipped; use the Wi-Fi or Ethernet interface.
- Protocol filtering supports TCP and UDP only, as the assignment specifies. Each IP or port filter matches one direction (source *or* destination).
- The summary *Length* column is the captured frame size, including the 14-byte Ethernet header. The IP total length is shown in the detailed view.
- Checksums are displayed but not verified.
- The payload text column is ASCII only; other text (for example non-English UTF-8) appears as `.`.
- **Privacy:** captures can include device names, local addresses and other identifying data. Do not commit packet dumps or share full payloads publicly. Only capture traffic you own or are authorized to analyze.

---

## 8. Member 1 — Packet capture and main program

*Member 1 (shanthu). Originally recorded in `MEMBER1_DOCUMENTATION.md`.*

### 8.1 Role

- `capture.py` — capture raw network frames, record timestamps and captured frame sizes.
- `main.py` — the command-line flow: request capture settings, call the parser, and connect the capture, filtering and display modules.

Member 1 also created the repository, pushed the starter project to GitHub and added the `.gitignore` (excluding `.venv/`, `__pycache__/`, `*.py[cod]` and `.DS_Store`).

### 8.2 Mac setup issue and workaround

On Member 1's Mac, Homebrew Python 3.14 failed when creating a virtual environment with `pip`: `platform.mac_ver()` returned an empty value, which also broke `pip` and `uv`. Reinstalling `python@3.14` did not help. The environment was created without pip, a local compatibility patch was added **inside the environment's `site-packages`** (not in the project files), and `uv` was used to install the dependency:

```bash
cd ~/CN_A3
python3.14 -m venv --without-pip .venv
source .venv/bin/activate

SITE="$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
mkdir -p "$SITE"

cat > "$SITE/_fix_macos_platform.py" <<'PY'
import os
import platform
import subprocess

_original_mac_ver = platform.mac_ver

def _patched_mac_ver(release="", versioninfo=("", "", ""), machine=""):
    r, v, m = _original_mac_ver(release, versioninfo, machine)
    if not r:
        try:
            r = subprocess.check_output(
                ["/usr/bin/sw_vers", "-productVersion"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            pass
    if not m:
        m = os.uname().machine
    return r, v, m

platform.mac_ver = _patched_mac_ver

_original_machine = platform.machine
def _patched_machine():
    return _original_machine() or os.uname().machine
platform.machine = _patched_machine
PY

printf 'import _fix_macos_platform\n' > "$SITE/zzz_fix_macos_platform.pth"
python -c "import platform; print('macOS:', platform.mac_ver()); print('Machine:', platform.machine())"

uv pip install --python .venv/bin/python -r requirements.txt
```

The check printed macOS `26.2` and machine `arm64`, and `scapy==2.8.0` was installed. This is a local workaround only; most computers do not need it and it must not be committed. Do not use `--break-system-packages` or install packages into Homebrew's system Python.

### 8.3 Concepts

- **Raw frame:** the bytes delivered by the capture layer, which can include a link-layer header.
- **IPv4 total length:** the size of the IPv4 packet including its header and transport data, but not the Ethernet header.
- **IPv4 header length:** from the IHL field; commonly 20 bytes.
- **Protocol number:** `6` is TCP; `17` is UDP.
- **UDP length:** includes the 8-byte UDP header and the payload.
- **TCP header length:** can be more than 20 bytes when TCP options are present.
- **Payload text:** a best-effort text view; not every payload is text. The hex view preserves the raw byte values.
- **Capture limits:** capture stops when either the packet count or the duration limit is reached.

### 8.4 Tests run and observed results (macOS)

- `uv 0.12.5`; Scapy 2.8.0 installed after the workaround; `python test_parser.py` printed `All parser tests passed!`; `capture.list_interfaces()` returned interfaces including `en0` and `lo0`.
- **Live UDP capture** (`en0`, 20 frames, 10 seconds): 20 raw frames captured and 8 IPv4 packets displayed with number, timestamp, addresses, ports, protocol and length. Packet 1 (UDP) had frame length 193, IPv4 total length 179, IPv4 header 20, UDP length 159 and UDP payload 151 bytes, which agree with the layout: 14 + 179 = 193, 20 + 159 = 179, 8 + 151 = 159.
- **Filtering:** `UDP` returned the 8 UDP packets; UDP with destination port `5353` returned 7 (the packet to port `1900` was excluded). An earlier mistaken test typed `5353` into the IP fields and returned nothing — IP fields need IP addresses. (The program now reports this as an invalid filter value.)
- **TCP capture** (500 frames, 15 seconds): 500 raw frames, 327 IPv4 packets, including TCP packets 279 and 280. The `TCP` filter returned those two. Packet 279 showed source port `443`, destination port `56927`, TCP header length `32` bytes, flags `PSH, ACK`, window `1921`, checksum `0xA30A`, payload `42` bytes. Some payloads were binary and did not decode into readable text, as expected.

### 8.5 Status

Completed: repository and starter project, Mac environment set up, offline tests passing, live captures on `en0`, UDP and TCP details viewed, filters tested through the menu. The remaining items Member 1 listed — a final integrated test after Members 2 and 3 finished, and a check on another teammate's computer — were completed by Member 3 on Windows (sections 6 and 10).

---

## 9. Member 2 — Packet parsing and testing

*Member 2 (palak). Originally recorded in `MEMBER1_DOCUMENTATION.md`; merged into `main` through pull request #1 (`parser-feature`).*

### 9.1 Objective and files

Packet parsing and parser testing: manually extracting IPv4, TCP and UDP header information from raw bytes without using Scapy to decode the headers.

- `parser.py` — improved UDP length validation.
- `test_parser.py` — added offline tests for invalid, incomplete and unusual packets.

### 9.2 Parsing concepts

- **Ethernet header:** bytes 12–13 identify the protocol type; `0x0800` is IPv4.
- **IPv4 header:** the first byte holds the version (upper four bits) and header length (lower four bits, multiplied by four).
- **Big-endian integers:** multi-byte fields such as IP total length and ports are decoded with `int.from_bytes(data, "big")`.
- **TCP header:** source and destination ports, sequence and acknowledgment numbers, header length, flags, window size, checksum and payload.
- **UDP header:** source and destination ports, UDP length (including the 8-byte header), checksum and payload.
- **Payload:** the bytes remaining after the transport header.

(Section 5 gives the full byte-offset tables.)

### 9.3 Improvement made

The UDP check now requires the declared UDP length to be at least 8 bytes **and** no larger than the IPv4 data length, except when the packet is the first fragment of a fragmented IPv4 packet (More Fragments flag set), which may carry only part of the UDP datagram. The dictionary returned by `parse_packet()` was kept unchanged for compatibility with the other modules.

### 9.4 Tests added

- `test_invalid_packets()` — an incomplete Ethernet frame and a non-IPv4 frame are ignored.
- `test_truncated_ip_header()` — an incomplete IPv4 header is ignored.
- `test_ipv4_options()` — an IPv4 header with options (24 bytes) is parsed.
- `test_invalid_tcp_header_length()` — an invalid TCP data offset produces no transport result.
- `test_invalid_udp_length()` — a UDP length below 8 bytes is rejected.
- `test_udp_length_exceeds_ip_payload()` — an unfragmented UDP length larger than the IPv4 data is rejected.

The original TCP and UDP tests were kept.

### 9.5 Verification

`python test_parser.py` printed `All parser tests passed!` and `git diff --check` reported no problems (Windows, Python 3.13, Scapy 2.8.0). The changes were committed on `parser-feature` as "Improve packet parser validation and tests", reviewed by Member 3 and merged into `main`.

### 9.6 Limitations noted

The tests cover selected valid and invalid packets; truncated payloads, fragmented packets and other malformed headers deserved more testing. (Member 3 later added a fragment test — section 10.4.)

---

## 10. Member 3 — Display, filters and final integration

*Member 3 (Manojna). Members 1 and 2 had finished their parts, so the final integration was also done by Member 3.*

### 10.1 Files

- `filters.py`, `display.py` — assigned files.
- `test_filters.py`, `test_display.py` — new tests; `test_parser.py` — one added test.
- `main.py`, `capture.py`, `parser.py`, `README.md` — integration, VLAN support and Windows support.

Member 3 also reviewed Member 2's pull request (ran all tests and checked fragment and padding cases by hand) and merged it into `main`.

### 10.2 Filtering (`filters.py`)

`filter_packets(packets, protocol, source_ip, destination_ip, source_port, destination_port)` returns the packets matching **all** filled-in filters; blank filters are ignored. The function name and arguments were kept, so `main.py` calls it as before.

| Filter | Accepted values | Notes |
|---|---|---|
| Protocol | `TCP`, `UDP` or blank | Not case sensitive. |
| Source / destination IP | A valid IPv4 address | Checked with `ipaddress`; `192.168.1.300` or `abc` is rejected. |
| Source / destination port | Whole number 0–65535 | Compared as numbers, so `0053` matches port 53. |

- **Invalid values** raise `ValueError` with a clear message; `main.py` prints e.g. `Invalid filter: Destination port must be a whole number from 0 to 65535. No filter applied.` Previously an invalid value silently returned no packets, which looked like "no matches".
- **Missing fields** are read with `packet.get(...)`, so incomplete packets do not crash the filter. A packet without ports never matches a port filter.

### 10.3 Display (`display.py`)

- **Summary:** number, time, source IP and port, destination IP and port, protocol, length; then a packet count and an explanation of the *Length* column and `-` (no port). An empty list prints `No matching IPv4 packets to display.`
- **Detailed view:** all required IP, TCP and UDP fields (section 4), plus the IP fragment offset. TCP/UDP packets with an incomplete header say the transport header is not available; other protocols (such as ICMP) say it is not decoded and show the IP payload.
- **Payload hex dump:** offset, 16 hex bytes per line, and the same bytes as text, with non-printable bytes shown as `.` so binary data or control characters cannot break the terminal output. Previously the hex was one very long line and the text was printed raw.
- **Missing values** show as `Unknown` instead of crashing.

### 10.4 Integration and Windows support

- **Interface selection.** On Windows Scapy names interfaces like `\Device\NPF_{49CD43C2-...}`, and the program defaulted to the macOS name `en0`. `capture.list_interfaces()` now returns each interface's friendly name, description and IP; `capture.default_interface()` returns Scapy's default; `main.py` (`choose_interface()`) lists them by number, marks the default, and accepts a number, a name or Enter. Still works with `en0` on macOS.
- **Capture error help** now includes a Windows hint (Npcap / run as Administrator).
- **VLAN-tagged frames (`parser.py`).** The live HTTP check showed the server's replies were missing. Inspecting the raw bytes showed those frames had EtherType `0x8100` (802.1Q VLAN tag), which the parser skipped. The parser now skips the 4-byte tag and reads the real EtherType at bytes 16–17, starting the IPv4 header at byte 18 (section 5). The returned dictionary is unchanged. Test: `test_vlan_tagged()`.
- **`test_parser.py`:** added `test_udp_fragments()` — a first fragment keeps its UDP header even though the UDP length exceeds the fragment; a later fragment is not decoded as UDP. This covers the case allowed by Member 2's change.
- **README:** Windows setup and a Tests section.

### 10.5 Tests

- `test_filters.py` (9 tests) and `test_display.py` (8 tests), described in section 6. The display tests use the same values as the assignment's sample packet (ports 49152→8080, sequence 105482, flags `PSH, ACK`, checksums `0x8A31`/`0x2F81`, payload `HELLO SERVER`).
- All three test files pass, and the live Windows capture check passed (section 6).

### 10.6 Assumptions

- Only TCP and UDP are offered as protocol filters, as specified.
- *Length* in the summary means captured frame size, consistent with the starter code and Member 1's tests.

# Member 1 Documentation — Packet Capture and Main Program

This document records my work so far on CN Assignment 3: Mini Packet Analyzer. It is intended to help me resume work later and explain my contribution to the group.

## 1. My role in the group

**Assigned files:**
- `capture.py` — capture raw network frames, record timestamps, and record captured frame sizes.
- `main.py` — provide the command-line flow, request capture settings, call the parser, and connect the capture, filtering, and display modules.

**Other members' main files:**
- Member 2: `parser.py` — manually decode IPv4, TCP, and UDP headers from raw packet bytes.
- Member 3: `filters.py` and `display.py` — filter captured packets and display packet summaries/details.

The modules work together: `main.py` asks for settings, `capture.py` collects raw frames, `parser.py` decodes supported packets, and `filters.py` / `display.py` let the user inspect the results.

## 2. Repository and local setup

Repository: `CN_A3`

Local folder used on my Mac: `~/CN_A3`

The project was cloned from the team's GitHub repository and the starter files were committed and pushed to `main`. The team is currently choosing to work on the shared `main` branch rather than create separate branches, so coordinate before editing overlapping files and pull teammates' changes before pushing.

### Normal setup on a computer where Python's virtual environment works normally

From the repository folder:

```bash
cd ~/CN_A3
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The active environment is indicated by `(.venv)` at the start of the Terminal prompt. The `.venv/` directory should not be committed to GitHub.

### My Mac's Python setup issue and workaround

On my Mac, Homebrew Python 3.14 initially failed when creating a virtual environment with `pip`. Python's `platform.mac_ver()` returned an empty value, which also caused `pip` and `uv` to fail. I reinstalled `python@3.14`, but the error remained.

I then created the environment without pip, added a local compatibility patch inside the environment's `site-packages`, and used `uv` to install the dependency. The following commands were successful on my machine:

```bash
cd ~/CN_A3
python3.14 -m venv --without-pip .venv
source .venv/bin/activate
```

The compatibility patch was saved **inside `.venv/lib/python3.14/site-packages/`**, not in the project source files. A `.pth` file loads it when Python starts. If I delete and recreate `.venv` on this Mac and encounter the same issue again, I can recreate the local workaround with the following commands while the new environment is activated:

```bash
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
```

On my Mac the check printed macOS version `26.2` and machine `arm64`. Then install the requirements with:

```bash
uv pip install --python .venv/bin/python -r requirements.txt
```

This installed `scapy==2.8.0`, and `python test_parser.py` passed. The workaround is a local environment fix only; it is not needed by every teammate and should not be committed to GitHub. Do not use `--break-system-packages` or install project packages into Homebrew's system Python.

### What is installed

`requirements.txt` includes Scapy. It is used to obtain raw frames for capture. The assignment requires the IPv4, TCP, and UDP header parsing to be student-implemented, so the core parsing should remain in `parser.py`, not delegated to Scapy.

## 3. How to run the program

Activate the environment if it is not already active:

```bash
cd ~/CN_A3
source .venv/bin/activate
```

Run the parser tests:

```bash
python test_parser.py
```

Expected result:

```text
All parser tests passed!
```

List available network interfaces:

```bash
python -c "from capture import list_interfaces; print(list_interfaces())"
```

Run the analyzer:

```bash
python main.py
```

The program asks for:
1. Network interface (the program suggested `en0` on my Mac).
2. Maximum number of captured packets/frames.
3. Capture duration in seconds.

During the capture window, normal network activity such as opening a website can create traffic. The capture stops when the packet/frame limit or the timer is reached. Use only networks and traffic that you own or are authorized to analyze.

The menu options are:
1. Show all packets.
2. Filter packets by protocol, source/destination IP, or source/destination port.
3. Inspect an individual packet, including its parsed headers and payload.
4. Exit.

## 4. Tests I ran and observed results

These results are from my local Mac and demonstrate that the starter program's current capture-to-display flow works on my machine. They are not a substitute for testing on other teammates' computers.

### Environment and offline parser test

- `uv --version` reported `uv 0.12.5`.
- `uv pip install --python .venv/bin/python -r requirements.txt` installed Scapy 2.8.0 successfully after the local environment workaround.
- `python test_parser.py` printed `All parser tests passed!`.
- `capture.list_interfaces()` returned network interfaces including `en0` and `lo0`.

### Live capture and UDP inspection

With `en0`, a maximum of 20 frames, and a 10-second limit, the program reported:

- 20 raw frames captured.
- 8 IPv4 packets parsed and displayed.
- The summary included packet number, timestamp, source/destination IP, source/destination port, protocol, and length.
- Inspecting packet 1 displayed an IPv4 header and UDP header, plus payload length, hexadecimal bytes, and a text representation.

The sample inspected UDP packet had a captured frame length of 193 bytes, IPv4 total length 179 bytes, IPv4 header length 20 bytes, UDP length 159 bytes, and UDP payload length 151 bytes. These lengths agree with the usual Ethernet/IPv4/UDP layout: 14 + 179 = 193, 20 + 159 = 179, and 8 + 151 = 159.

### Filtering tests

Using that capture:

- Filtering by `UDP` with all other filters blank returned the 8 displayed UDP packets.
- Filtering by UDP and destination port `5353` returned 7 packets; the packet sent to destination port `1900` was excluded.
- An earlier incorrect test entered `5353` in the source and destination IP fields and returned no results. IP fields need IP addresses; port fields need port numbers.

### TCP test

With a maximum of 500 frames and a 15-second limit, the program reported:

- 500 raw frames captured.
- 327 IPv4 packets parsed.
- The list contained TCP packets numbered 279 and 280, among many UDP packets.
- Filtering by `TCP` returned those two TCP packets.
- Inspecting packet 279 showed TCP source port `443`, destination port `56927`, TCP header length `32` bytes, flags `PSH, ACK`, window size `1921`, checksum `0xA30A`, and payload length `42` bytes.

This confirms that the current program captured and displayed TCP traffic as well as UDP traffic during that test. Some captured payloads were binary and did not decode into readable text; that is expected.

## 5. Useful concepts to explain

- **Raw frame:** the bytes delivered by the capture layer. The captured frame size can include a link-layer header.
- **IPv4 total length:** the size of the IPv4 packet, including its IPv4 header and transport data, but not the Ethernet header.
- **IPv4 header length:** found from the Internet Header Length (IHL) field; a common value is 20 bytes.
- **Protocol number:** `6` means TCP; `17` means UDP.
- **UDP length:** includes the 8-byte UDP header and UDP payload.
- **TCP header length:** may be larger than 20 bytes because TCP options can be present.
- **Payload text:** a best-effort text interpretation; not every payload is text. The hexadecimal representation preserves the raw byte values.
- **Capture limits:** the program stops when either the selected packet/frame count or duration limit is reached.

## 6. Current status and remaining work

### Completed and verified on my Mac

- Cloned the repository and pushed the starter project to GitHub.
- Set up a local Python environment and installed the capture dependency.
- Confirmed the offline parser tests pass.
- Listed network interfaces and completed live captures on `en0`.
- Viewed packet summaries and detailed UDP and TCP packet information.
- Tested UDP, destination-port, and TCP filtering through the menu.
- Created a local `.gitignore` intended to exclude `.venv/`, `__pycache__/`, `*.py[cod]`, and `.DS_Store`.

### Still to do

- Check `git status` and commit/push `MEMBER1_DOCUMENTATION.md` and `.gitignore` if they are not already committed.
- Review `capture.py` and `main.py` and make a clearly identifiable code improvement if required by the group/assignment; most of the work recorded above is testing and environment setup, not a claim that all starter code was written by me.
- Run a final integrated test after Members 2 and 3 finish their changes.
- Confirm the project runs from a fresh setup on at least one teammate's computer.

## 7. Saving this documentation to GitHub

Save this file at the top level of the repository as `MEMBER1_DOCUMENTATION.md` (next to `main.py`, `capture.py`, and `README.md`). Then run:

```bash
git status
git add MEMBER1_DOCUMENTATION.md .gitignore
git commit -m "Document Member 1 capture and testing"
git pull --rebase origin main
git push origin main
```

Because we are sharing `main`, coordinate with the other two members before pushing. If Git reports a conflict or rejects the push, stop and review the message rather than force-pushing.

## Privacy note

My packet captures included local network discovery traffic. Payloads can contain device names, local addresses, or other identifying information, so do not commit raw packet dumps or share full payloads publicly. Only capture traffic that you are authorized to analyze.


## Member 2 — Packet Parsing and Testing

### 1. Objective

Member 2 was responsible for packet parsing and parser testing in the Mini Packet Analyzer project. The work focused on manually extracting IPv4, TCP, and UDP header information from raw packet bytes without using Scapy to decode these headers.

### 2. Files Worked On

- `parser.py` — improved UDP length validation.
- `test_parser.py` — added offline tests for invalid, incomplete, and unusual packets.

### 3. Packet Parsing Concepts

**Ethernet header:** The parser reads bytes 12–13 to identify the Ethernet protocol type. The value `0x0800` indicates IPv4.

**IPv4 header:** The first byte contains the IP version in its upper four bits and the header length in its lower four bits. The header length is multiplied by four to obtain the number of bytes.

**Big-endian integers:** Multi-byte fields, such as IP total length and transport ports, are decoded using Python's `int.from_bytes(data, "big")`.

**TCP header:** The parser extracts source and destination ports, sequence number, acknowledgement number, header length, flags, window size, checksum, and payload.

**UDP header:** The parser extracts source and destination ports, UDP length, checksum, and payload. The UDP length includes the eight-byte UDP header.

**Payload:** The parser separates transport headers from the remaining payload bytes.

### 4. Improvements Made

The UDP validation condition in `parser.py` was improved to check that the declared UDP length is at least eight bytes and does not exceed the IPv4 payload length, except when the IPv4 packet is marked as a fragment that may contain only part of the UDP datagram.

The existing dictionary structure returned by `parse_packet()` was preserved to maintain compatibility with the other project modules.

### 5. Tests Added

The following tests were added to `test_parser.py`:

- `test_invalid_packets()` — checks that an incomplete Ethernet frame and a non-IPv4 Ethernet frame are ignored.
- `test_truncated_ip_header()` — checks that an incomplete IPv4 header is ignored.
- `test_ipv4_options()` — checks parsing of an IPv4 header containing options.
- `test_invalid_tcp_header_length()` — checks that an invalid TCP header length does not produce a valid transport result.
- `test_invalid_udp_length()` — checks that a UDP length smaller than eight bytes is rejected.
- `test_udp_length_exceeds_ip_payload()` — checks that an unfragmented UDP length exceeding the IPv4 payload length is rejected.

The original TCP and UDP parsing tests were retained.

### 6. Verification

The following commands were run successfully during development:

```text
python test_parser.py
All parser tests passed!
```

```text
git diff --check
```

The parser tests were run locally on Windows using Python 3.13 and Scapy 2.8.0. The tests construct sample packet bytes locally and do not require live network capture.

### 7. GitHub Contribution

The changes were committed on the `parser-feature` branch with commit message:

`Improve packet parser validation and tests`

The branch was pushed to GitHub for review before merging into `main`.

### 8. Limitations and Further Testing

The offline tests cover selected valid and invalid packet cases. Additional testing is still recommended for truncated packet payloads, fragmented IPv4 packets, and other malformed headers. Passing the current tests does not guarantee that every malformed packet is handled correctly.
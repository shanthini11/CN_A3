"""Small offline tests for display.py. These do not capture live network traffic."""

import io
from contextlib import redirect_stdout

from display import hex_dump, printable_text, show_details, show_summary
from parser import parse_packet
from test_parser import make_packet


def capture_output(function, *args):
    # Run a display function and return what it printed.
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        function(*args)
    return buffer.getvalue()


def make_tcp(payload):
    tcp_header = (
        (49152).to_bytes(2, "big")
        + (8080).to_bytes(2, "big")
        + (105482).to_bytes(4, "big")
        + (208713).to_bytes(4, "big")
        + bytes([0x50, 0x18])  # 20-byte TCP header; PSH + ACK flags.
        + (65535).to_bytes(2, "big")
        + (0x2F81).to_bytes(2, "big")
        + b"\x00\x00"
    )
    return parse_packet(make_packet(6, tcp_header, payload), 17, "14:32:08.421")


def make_udp(payload):
    udp_header = (
        (53000).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + (0x1234).to_bytes(2, "big")
    )
    return parse_packet(make_packet(17, udp_header, payload), 2, "12:00:01.000")


def test_summary_fields():
    output = capture_output(show_summary, [make_tcp(b"HELLO"), make_udp(b"HI")])
    for text in ("No.", "Source IP", "Destination IP", "Protocol", "Src Port",
                 "Dst Port", "Length", "192.168.1.10", "192.168.1.20",
                 "49152", "8080", "53000", "TCP", "UDP", "2 packet(s) shown"):
        assert text in output, text


def test_summary_empty():
    assert "No matching IPv4 packets" in capture_output(show_summary, [])


def test_summary_missing_values():
    output = capture_output(show_summary, [{"number": 1, "protocol": "ICMP"}])
    assert "Unknown" in output
    assert "-" in output


def test_tcp_details():
    output = capture_output(show_details, make_tcp(b"HELLO SERVER"))
    for text in ("PACKET #17", "14:32:08.421", "IP HEADER", "Version: 4",
                 "Header length: 20 bytes", "Total length: 52 bytes", "TTL: 64",
                 "Protocol: TCP (number 6)", "Header checksum: 0x8A31",
                 "Source IP: 192.168.1.10", "Destination IP: 192.168.1.20",
                 "TCP HEADER", "Source port: 49152", "Destination port: 8080",
                 "Sequence number: 105482", "Acknowledgment number: 208713",
                 "Flags: PSH, ACK", "Window size: 65535", "Checksum: 0x2F81",
                 "Payload length: 12 bytes", "PAYLOAD",
                 "48 45 4C 4C 4F 20 53 45 52 56 45 52", "HELLO SERVER"):
        assert text in output, text


def test_udp_details():
    output = capture_output(show_details, make_udp(b"HI"))
    for text in ("UDP HEADER", "Source port: 53000", "Destination port: 53",
                 "Length: 10 bytes", "Checksum: 0x1234", "Payload length: 2 bytes",
                 "48 49", "HI"):
        assert text in output, text


def test_empty_payload():
    output = capture_output(show_details, make_tcp(b""))
    assert "Payload length: 0 bytes" in output
    assert "Empty payload." in output


def test_missing_details():
    # A packet missing header data should print "Unknown" instead of crashing.
    output = capture_output(show_details, {"number": 3, "protocol": "TCP", "transport": None})
    assert "Version: Unknown" in output
    assert "Transport header: not available" in output
    assert "Empty payload." in output


def test_unprintable_payload():
    # Control characters and binary bytes are shown as '.' in the text column.
    assert printable_text(b"A\x1b[31m\r\n\x00\xffB") == "A.[31m....B"
    lines = hex_dump(bytes(range(20)))
    assert len(lines) == 2
    assert lines[0].startswith("0000    00 01 02")
    assert lines[1].startswith("0010    10 11 12 13")


if __name__ == "__main__":
    test_summary_fields()
    test_summary_empty()
    test_summary_missing_values()
    test_tcp_details()
    test_udp_details()
    test_empty_payload()
    test_missing_details()
    test_unprintable_payload()
    print("All display tests passed!")

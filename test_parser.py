"""Small offline tests for parser.py. These do not capture live network traffic."""

import ipaddress
from parser import parse_packet


def make_packet(protocol_number, transport_bytes, payload):
    # Simple Ethernet header: 12 MAC-address bytes + IPv4 type 0x0800.
    ethernet = b"\x00" * 12 + b"\x08\x00"

    total_length = 20 + len(transport_bytes) + len(payload)
    ip_header = (
        bytes([0x45, 0x00])
        + total_length.to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (0x4000).to_bytes(2, "big")
        + bytes([64, protocol_number])
        + (0x8A31).to_bytes(2, "big")
        + ipaddress.IPv4Address("192.168.1.10").packed
        + ipaddress.IPv4Address("192.168.1.20").packed
    )
    return ethernet + ip_header + transport_bytes + payload


def test_tcp():
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
    raw = make_packet(6, tcp_header, b"HELLO")
    packet = parse_packet(raw, 1, "12:00:00.000")
    assert packet is not None
    assert packet["protocol"] == "TCP"
    assert packet["src_port"] == 49152
    assert packet["dst_port"] == 8080
    assert packet["transport"]["sequence_number"] == 105482
    assert packet["transport"]["flags"] == "PSH, ACK"
    assert packet["payload"] == b"HELLO"


def test_udp():
    payload = b"HI"
    udp_header = (
        (53000).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + (0x1234).to_bytes(2, "big")
    )
    raw = make_packet(17, udp_header, payload)
    packet = parse_packet(raw, 2, "12:00:01.000")
    assert packet is not None
    assert packet["protocol"] == "UDP"
    assert packet["src_port"] == 53000
    assert packet["dst_port"] == 53
    assert packet["transport"]["length"] == 10
    assert packet["payload"] == b"HI"

def test_invalid_packets():
    # An incomplete Ethernet frame should be ignored.
    assert parse_packet(b"\x00" * 10, 1, "12:00:00") is None

    # A non-IPv4 Ethernet frame should be ignored.
    non_ipv4 = b"\x00" * 12 + b"\x86\xdd" + b"\x00" * 40
    assert parse_packet(non_ipv4, 2, "12:00:01") is None


def test_truncated_ip_header():
    # Ethernet header followed by an incomplete IPv4 header.
    raw = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 10
    assert parse_packet(raw, 3, "12:00:02") is None

def test_ipv4_options():
    # IPv4 header with options: header length is 24 bytes.
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ip_header = (
        bytes([0x46, 0x00])
        + (24).to_bytes(2, "big")
        + b"\x00\x01\x00\x00"
        + bytes([64, 99])
        + b"\x00\x00"
        + ipaddress.IPv4Address("192.168.1.10").packed
        + ipaddress.IPv4Address("192.168.1.20").packed
        + b"\x01\x01\x01\x01"
    )

    packet = parse_packet(ethernet + ip_header, 4, "12:00:03")
    assert packet is not None
    assert packet["ip"]["header_length"] == 24
    assert packet["protocol"] == "OTHER"


def test_invalid_tcp_header_length():
    # TCP data-offset field says 16 bytes, which is invalid.
    tcp_header = (
        (1234).to_bytes(2, "big")
        + (80).to_bytes(2, "big")
        + b"\x00" * 8
        + bytes([0x40, 0x10])
        + b"\x00" * 6
    )
    raw = make_packet(6, tcp_header, b"")

    packet = parse_packet(raw, 5, "12:00:04")
    assert packet is not None
    assert packet["src_port"] is None
    assert packet["transport"] is None


def test_invalid_udp_length():
    # UDP length says 4 bytes, less than the 8-byte UDP header.
    udp_header = (
        (1234).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (4).to_bytes(2, "big")
        + b"\x00\x00"
    )
    raw = make_packet(17, udp_header, b"")

    packet = parse_packet(raw, 6, "12:00:05")
    assert packet is not None
    assert packet["src_port"] is None
    assert packet["transport"] is None

def test_udp_length_exceeds_ip_payload():
    udp_header = (
        (1234).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (12).to_bytes(2, "big")
        + b"\x00\x00"
    )
    raw = make_packet(17, udp_header, b"")

    packet = parse_packet(raw, 7, "12:00:06")
    assert packet is not None
    assert packet["transport"] is None
    assert packet["src_port"] is None
    assert packet["dst_port"] is None

if __name__ == "__main__":
    test_tcp()
    test_udp()
    test_invalid_packets()
    test_truncated_ip_header()
    test_ipv4_options()
    test_invalid_tcp_header_length()
    test_invalid_udp_length()
    test_udp_length_exceeds_ip_payload()
    print("All parser tests passed!")

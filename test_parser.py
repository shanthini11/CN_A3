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


if __name__ == "__main__":
    test_tcp()
    test_udp()
    print("All parser tests passed!")

"""Small offline tests for filters.py. These do not capture live network traffic."""

from filters import filter_packets
from parser import parse_packet
from test_parser import make_packet


def make_summary(number, protocol, src_ip, dst_ip, src_port, dst_port):
    # Only the summary fields that filters.py uses.
    return {
        "number": number,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
    }


PACKETS = [
    make_summary(1, "TCP", "192.168.1.10", "142.250.1.1", 49152, 443),
    make_summary(2, "UDP", "192.168.1.10", "8.8.8.8", 53000, 53),
    make_summary(3, "TCP", "142.250.1.1", "192.168.1.10", 443, 49152),
    make_summary(4, "ICMP", "192.168.1.10", "8.8.8.8", None, None),
    make_summary(5, "UDP", "192.168.1.20", "224.0.0.251", 5353, 5353),
]


def numbers(packets):
    return [packet["number"] for packet in packets]


def test_no_filters():
    assert numbers(filter_packets(PACKETS)) == [1, 2, 3, 4, 5]


def test_protocol():
    assert numbers(filter_packets(PACKETS, protocol="TCP")) == [1, 3]
    assert numbers(filter_packets(PACKETS, protocol="udp")) == [2, 5]
    assert numbers(filter_packets(PACKETS, protocol=" Tcp ")) == [1, 3]


def test_ip():
    assert numbers(filter_packets(PACKETS, source_ip="192.168.1.10")) == [1, 2, 4]
    assert numbers(filter_packets(PACKETS, destination_ip="8.8.8.8")) == [2, 4]


def test_port():
    assert numbers(filter_packets(PACKETS, source_port="443")) == [3]
    assert numbers(filter_packets(PACKETS, destination_port="53")) == [2]
    assert numbers(filter_packets(PACKETS, destination_port=443)) == [1]
    # Leading zeros are the same port number.
    assert numbers(filter_packets(PACKETS, destination_port="0053")) == [2]


def test_combined():
    result = filter_packets(PACKETS, protocol="UDP", source_ip="192.168.1.10",
                            destination_port="53")
    assert numbers(result) == [2]


def test_no_match():
    assert filter_packets(PACKETS, protocol="TCP", destination_port="53") == []
    assert filter_packets(PACKETS, source_ip="10.0.0.1") == []
    assert filter_packets([], protocol="TCP") == []


def test_missing_fields():
    # Packets without ports (ICMP) never match a port filter.
    assert 4 not in numbers(filter_packets(PACKETS, source_port="0"))
    # A packet missing fields entirely should not crash the filter.
    assert filter_packets([{"number": 9}], protocol="TCP", source_ip="1.2.3.4",
                          source_port="80") == []
    assert numbers(filter_packets([{"number": 9}])) == [9]


def test_invalid_values():
    invalid = [
        {"protocol": "ICMP"},
        {"source_ip": "192.168.1"},
        {"destination_ip": "not-an-ip"},
        {"source_ip": "192.168.1.300"},
        {"source_port": "abc"},
        {"destination_port": "70000"},
        {"source_port": "-1"},
    ]
    for kwargs in invalid:
        try:
            filter_packets(PACKETS, **kwargs)
        except ValueError:
            continue
        raise AssertionError(f"Expected ValueError for {kwargs}")

    # None is treated the same as a blank filter.
    assert len(filter_packets(PACKETS, protocol=None, source_ip=None,
                              source_port=None)) == len(PACKETS)


def test_parsed_packets():
    # Filters must work on the real dictionaries produced by parse_packet().
    tcp_header = (
        (49152).to_bytes(2, "big")
        + (8080).to_bytes(2, "big")
        + b"\x00" * 8
        + bytes([0x50, 0x18])
        + b"\x00" * 6
    )
    udp_header = (53000).to_bytes(2, "big") + (53).to_bytes(2, "big") + (8).to_bytes(2, "big") + b"\x00\x00"
    packets = [
        parse_packet(make_packet(6, tcp_header, b"HELLO"), 1, "12:00:00.000"),
        parse_packet(make_packet(17, udp_header, b""), 2, "12:00:01.000"),
    ]
    assert numbers(filter_packets(packets, protocol="TCP", destination_port="8080")) == [1]
    assert numbers(filter_packets(packets, protocol="UDP", source_ip="192.168.1.10",
                                  destination_ip="192.168.1.20", source_port="53000")) == [2]


if __name__ == "__main__":
    test_no_filters()
    test_protocol()
    test_ip()
    test_port()
    test_combined()
    test_no_match()
    test_missing_fields()
    test_invalid_values()
    test_parsed_packets()
    print("All filter tests passed!")

"""Simple packet filters."""

import ipaddress


def normalize_protocol(value):
    """Return "TCP", "UDP" or "" (no filter). Raise ValueError otherwise."""
    protocol = str(value or "").strip().upper()
    if protocol not in ("", "TCP", "UDP"):
        raise ValueError("Protocol must be TCP, UDP, or blank.")
    return protocol


def normalize_ip(value, label):
    """Return a standard IPv4 address string or "" (no filter).

    Raise ValueError if the value is not a valid IPv4 address.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise ValueError(f"{label} must be an IPv4 address such as 192.168.1.10.") from None


def normalize_port(value, label):
    """Return a port number from 0 to 65535, or None (no filter).

    Raise ValueError if the value is not a whole number in that range.
    """
    text = str(value if value is not None else "").strip()
    if not text:
        return None
    if not (text.isascii() and text.isdigit()) or int(text) > 65535:
        raise ValueError(f"{label} must be a whole number from 0 to 65535.")
    return int(text)


def filter_packets(packets, protocol="", source_ip="", destination_ip="",
                   source_port="", destination_port=""):
    """Return packets matching all supplied filters. Empty filters are ignored.

    Raise ValueError if a filter value is invalid. A packet missing a field
    (for example, no ports because its TCP/UDP header was incomplete) does not
    match a filter on that field.
    """
    protocol = normalize_protocol(protocol)
    source_ip = normalize_ip(source_ip, "Source IP")
    destination_ip = normalize_ip(destination_ip, "Destination IP")
    source_port = normalize_port(source_port, "Source port")
    destination_port = normalize_port(destination_port, "Destination port")

    result = []
    for packet in packets:
        if protocol and packet.get("protocol") != protocol:
            continue
        if source_ip and packet.get("src_ip") != source_ip:
            continue
        if destination_ip and packet.get("dst_ip") != destination_ip:
            continue
        if source_port is not None and packet.get("src_port") != source_port:
            continue
        if destination_port is not None and packet.get("dst_port") != destination_port:
            continue
        result.append(packet)

    return result

"""Simple packet filters."""


def filter_packets(packets, protocol="", source_ip="", destination_ip="",
                   source_port="", destination_port=""):
    """Return packets matching all supplied filters. Empty filters are ignored."""
    result = []
    protocol = protocol.strip().upper()

    for packet in packets:
        if protocol and packet["protocol"] != protocol:
            continue
        if source_ip and packet["src_ip"] != source_ip:
            continue
        if destination_ip and packet["dst_ip"] != destination_ip:
            continue
        if source_port and str(packet["src_port"]) != source_port:
            continue
        if destination_port and str(packet["dst_port"]) != destination_port:
            continue
        result.append(packet)

    return result

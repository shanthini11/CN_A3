"""Manual IPv4, TCP and UDP header parser for the Mini Packet Analyzer."""

import ipaddress


def parse_packet(raw_packet, number, timestamp):
    """Parse an Ethernet frame containing IPv4. Return a dictionary or None.

    Only raw bytes are used here. Scapy is not used to decode the headers.
    This simple version expects a normal 14-byte Ethernet header, or an
    18-byte header with one 802.1Q VLAN tag.
    """
    if len(raw_packet) < 14:
        return None

    # Ethernet header: bytes 12-13 contain the packet type.
    ethernet_type = int.from_bytes(raw_packet[12:14], "big")
    ip_start = 14

    # 0x8100 means a 4-byte VLAN tag follows (2 bytes 0x8100 + 2 bytes VLAN ID),
    # so the real packet type is at bytes 16-17 and IPv4 starts 4 bytes later.
    if ethernet_type == 0x8100 and len(raw_packet) >= 18:
        ethernet_type = int.from_bytes(raw_packet[16:18], "big")
        ip_start = 18

    if ethernet_type != 0x0800:  # 0x0800 means IPv4.
        return None

    if len(raw_packet) < ip_start + 20:
        return None

    first_byte = raw_packet[ip_start]
    version = first_byte >> 4
    ip_header_length = (first_byte & 0x0F) * 4

    if version != 4 or ip_header_length < 20:
        return None
    if len(raw_packet) < ip_start + ip_header_length:
        return None

    total_length = int.from_bytes(raw_packet[ip_start + 2:ip_start + 4], "big")
    if total_length < ip_header_length:
        return None

    ttl = raw_packet[ip_start + 8]
    protocol_number = raw_packet[ip_start + 9]
    ip_checksum = int.from_bytes(raw_packet[ip_start + 10:ip_start + 12], "big")
    source_ip = str(ipaddress.IPv4Address(raw_packet[ip_start + 12:ip_start + 16]))
    destination_ip = str(ipaddress.IPv4Address(raw_packet[ip_start + 16:ip_start + 20]))

    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol = protocol_names.get(protocol_number, "OTHER")

    # Use the IP total length so Ethernet padding is not treated as payload.
    available_ip_length = min(total_length, len(raw_packet) - ip_start)
    ip_end = ip_start + available_ip_length
    transport_start = ip_start + ip_header_length
    ip_payload = raw_packet[transport_start:ip_end]

    # A non-zero fragment offset means this is not the first IP fragment.
    fragment_field = int.from_bytes(raw_packet[ip_start + 6:ip_start + 8], "big")
    fragment_offset = fragment_field & 0x1FFF

    source_port = None
    destination_port = None
    transport = None
    payload = b""

    if fragment_offset == 0 and protocol == "TCP" and len(ip_payload) >= 20:
        source_port = int.from_bytes(ip_payload[0:2], "big")
        destination_port = int.from_bytes(ip_payload[2:4], "big")
        sequence_number = int.from_bytes(ip_payload[4:8], "big")
        acknowledgment_number = int.from_bytes(ip_payload[8:12], "big")
        tcp_header_length = (ip_payload[12] >> 4) * 4
        flags_byte = ip_payload[13]
        window_size = int.from_bytes(ip_payload[14:16], "big")
        tcp_checksum = int.from_bytes(ip_payload[16:18], "big")

        if tcp_header_length >= 20 and len(ip_payload) >= tcp_header_length:
            flag_list = [
                ("FIN", 0x01),
                ("SYN", 0x02),
                ("RST", 0x04),
                ("PSH", 0x08),
                ("ACK", 0x10),
                ("URG", 0x20),
                ("ECE", 0x40),
                ("CWR", 0x80),
            ]
            flags = [name for name, mask in flag_list if flags_byte & mask]
            payload = ip_payload[tcp_header_length:]
            transport = {
                "source_port": source_port,
                "destination_port": destination_port,
                "sequence_number": sequence_number,
                "acknowledgment_number": acknowledgment_number,
                "header_length": tcp_header_length,
                "flags": ", ".join(flags) if flags else "None",
                "window_size": window_size,
                "checksum": tcp_checksum,
                "payload_length": len(payload),
            }

    elif fragment_offset == 0 and protocol == "UDP" and len(ip_payload) >= 8:
        source_port = int.from_bytes(ip_payload[0:2], "big")
        destination_port = int.from_bytes(ip_payload[2:4], "big")
        udp_length = int.from_bytes(ip_payload[4:6], "big")
        udp_checksum = int.from_bytes(ip_payload[6:8], "big")

        if udp_length >= 8 and (
            udp_length <= total_length - ip_header_length
            or (fragment_field & 0x2000)
        ):
            payload_end = min(udp_length, len(ip_payload))
            payload = ip_payload[8:payload_end]
            transport = {
                "source_port": source_port,
                "destination_port": destination_port,
                "length": udp_length,
                "checksum": udp_checksum,
                "payload_length": len(payload),
            }

    elif protocol not in ("TCP", "UDP"):
        payload = ip_payload

    # If the TCP/UDP header is incomplete, leave ports and transport as None.
    if transport is None:
        source_port = None
        destination_port = None

    return {
        "number": number,
        "time": timestamp,
        "size": len(raw_packet),
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "protocol": protocol,
        "src_port": source_port,
        "dst_port": destination_port,
        "ip": {
            "version": version,
            "header_length": ip_header_length,
            "total_length": total_length,
            "ttl": ttl,
            "protocol_number": protocol_number,
            "protocol_name": protocol,
            "checksum": ip_checksum,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "fragment_offset": fragment_offset,
        },
        "transport": transport,
        "payload": payload,
    }

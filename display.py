"""Command-line packet summary and detail display."""

BYTES_PER_LINE = 16


def show_value(value, unit=""):
    """Return a value as text, or "Unknown" if it is missing."""
    if value is None or value == "":
        return "Unknown"
    return f"{value} {unit}".strip()


def show_hex(value):
    """Return a checksum such as 0x8A31, or "Unknown" if it is missing."""
    if not isinstance(value, int):
        return "Unknown"
    return f"0x{value:04X}"


def printable_text(data):
    """Return bytes as text, replacing non-printable bytes with '.'.

    Only printable ASCII (0x20-0x7E) is shown, so binary data or control
    characters (newlines, escape codes) cannot break the terminal output.
    """
    return "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in data)


def hex_dump(data):
    """Return payload lines as: offset, 16 bytes in hex, then the same bytes as text."""
    lines = []
    for offset in range(0, len(data), BYTES_PER_LINE):
        chunk = data[offset:offset + BYTES_PER_LINE]
        hex_part = chunk.hex(" ").upper()
        lines.append(f"{offset:04X}    {hex_part:<{BYTES_PER_LINE * 3 - 1}}  {printable_text(chunk)}")
    return lines


def show_summary(packets):
    if not packets:
        print("No matching IPv4 packets to display.")
        return

    header = (f"{'No.':<5} {'Time':<13} {'Source IP':<16} {'Src Port':<9} "
              f"{'Destination IP':<16} {'Dst Port':<9} {'Protocol':<9} {'Length':<8}")
    print()
    print(header)
    print("-" * len(header))

    for packet in packets:
        source_port = packet.get("src_port")
        destination_port = packet.get("dst_port")
        print(f"{show_value(packet.get('number')):<5} {show_value(packet.get('time')):<13} "
              f"{show_value(packet.get('src_ip')):<16} "
              f"{'-' if source_port is None else source_port:<9} "
              f"{show_value(packet.get('dst_ip')):<16} "
              f"{'-' if destination_port is None else destination_port:<9} "
              f"{show_value(packet.get('protocol')):<9} {show_value(packet.get('size')):<8}")

    print(f"\n{len(packets)} packet(s) shown. Length = captured frame size in bytes. "
          "'-' = no port (not TCP/UDP, or header incomplete).\n")


def show_details(packet):
    print("\n" + "=" * 50)
    print(f"PACKET #{show_value(packet.get('number'))}")
    print(f"Time: {show_value(packet.get('time'))}")
    print(f"Packet length: {show_value(packet.get('size'), 'bytes')} (captured frame)")

    ip = packet.get("ip") or {}
    print("\nIP HEADER")
    print("-" * 30)
    print(f"Version: {show_value(ip.get('version'))}")
    print(f"Header length: {show_value(ip.get('header_length'), 'bytes')}")
    print(f"Total length: {show_value(ip.get('total_length'), 'bytes')}")
    print(f"TTL: {show_value(ip.get('ttl'))}")
    print(f"Protocol: {show_value(ip.get('protocol_name'))} "
          f"(number {show_value(ip.get('protocol_number'))})")
    print(f"Header checksum: {show_hex(ip.get('checksum'))}")
    print(f"Source IP: {show_value(ip.get('source_ip'))}")
    print(f"Destination IP: {show_value(ip.get('destination_ip'))}")
    print(f"Fragment offset: {show_value(ip.get('fragment_offset'))}")

    protocol = packet.get("protocol")
    transport = packet.get("transport")
    if transport is not None and protocol == "TCP":
        print("\nTCP HEADER")
        print("-" * 30)
        print(f"Source port: {show_value(transport.get('source_port'))}")
        print(f"Destination port: {show_value(transport.get('destination_port'))}")
        print(f"Sequence number: {show_value(transport.get('sequence_number'))}")
        print(f"Acknowledgment number: {show_value(transport.get('acknowledgment_number'))}")
        print(f"Header length: {show_value(transport.get('header_length'), 'bytes')}")
        print(f"Flags: {show_value(transport.get('flags'))}")
        print(f"Window size: {show_value(transport.get('window_size'))}")
        print(f"Checksum: {show_hex(transport.get('checksum'))}")
        print(f"Payload length: {show_value(transport.get('payload_length'), 'bytes')}")

    elif transport is not None and protocol == "UDP":
        print("\nUDP HEADER")
        print("-" * 30)
        print(f"Source port: {show_value(transport.get('source_port'))}")
        print(f"Destination port: {show_value(transport.get('destination_port'))}")
        print(f"Length: {show_value(transport.get('length'), 'bytes')}")
        print(f"Checksum: {show_hex(transport.get('checksum'))}")
        print(f"Payload length: {show_value(transport.get('payload_length'), 'bytes')}")

    elif protocol in ("TCP", "UDP"):
        print("\nTransport header: not available (fragment or incomplete packet).")
    else:
        print(f"\nTransport header: {show_value(protocol)} is not decoded; "
              "the IP payload is shown below.")

    payload = packet.get("payload") or b""
    print("\nPAYLOAD")
    print("-" * 30)
    print(f"Payload length: {len(payload)} bytes")
    if not payload:
        print("Empty payload.")
    else:
        print("Offset  Hex" + " " * (BYTES_PER_LINE * 3 - 2) + "Text")
        for line in hex_dump(payload):
            print(line)
    print("=" * 50 + "\n")

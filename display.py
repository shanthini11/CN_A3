"""Command-line packet summary and detail display."""


def show_summary(packets):
    if not packets:
        print("No matching IPv4 packets to display.")
        return

    print()
    print(f"{'No.':<5} {'Time':<13} {'Source IP':<16} {'Src Port':<9} "
          f"{'Destination IP':<16} {'Dst Port':<9} {'Protocol':<9} {'Length':<8}")
    print("-" * 91)

    for packet in packets:
        source_port = packet["src_port"] if packet["src_port"] is not None else "-"
        destination_port = packet["dst_port"] if packet["dst_port"] is not None else "-"
        print(f"{packet['number']:<5} {packet['time']:<13} "
              f"{packet['src_ip']:<16} {str(source_port):<9} "
              f"{packet['dst_ip']:<16} {str(destination_port):<9} "
              f"{packet['protocol']:<9} {packet['size']:<8}")
    print()


def show_details(packet):
    print("\n" + "=" * 50)
    print(f"PACKET #{packet['number']}")
    print(f"Time: {packet['time']}")
    print(f"Packet length: {packet['size']} bytes (captured frame)")

    ip = packet["ip"]
    print("\nIP HEADER")
    print("-" * 30)
    print(f"Version: {ip['version']}")
    print(f"Header length: {ip['header_length']} bytes")
    print(f"Total length: {ip['total_length']} bytes")
    print(f"TTL: {ip['ttl']}")
    print(f"Protocol: {ip['protocol_name']} (number {ip['protocol_number']})")
    print(f"Header checksum: 0x{ip['checksum']:04X}")
    print(f"Source IP: {ip['source_ip']}")
    print(f"Destination IP: {ip['destination_ip']}")

    transport = packet["transport"]
    if transport is not None and packet["protocol"] == "TCP":
        print("\nTCP HEADER")
        print("-" * 30)
        print(f"Source port: {transport['source_port']}")
        print(f"Destination port: {transport['destination_port']}")
        print(f"Sequence number: {transport['sequence_number']}")
        print(f"Acknowledgment number: {transport['acknowledgment_number']}")
        print(f"Header length: {transport['header_length']} bytes")
        print(f"Flags: {transport['flags']}")
        print(f"Window size: {transport['window_size']}")
        print(f"Checksum: 0x{transport['checksum']:04X}")
        print(f"Payload length: {transport['payload_length']} bytes")

    elif transport is not None and packet["protocol"] == "UDP":
        print("\nUDP HEADER")
        print("-" * 30)
        print(f"Source port: {transport['source_port']}")
        print(f"Destination port: {transport['destination_port']}")
        print(f"Length: {transport['length']} bytes")
        print(f"Checksum: 0x{transport['checksum']:04X}")
        print(f"Payload length: {transport['payload_length']} bytes")

    elif packet["protocol"] in ("TCP", "UDP"):
        print("\nTransport header: not available (fragment or incomplete packet).")

    payload = packet["payload"]
    print("\nPAYLOAD")
    print("-" * 30)
    print(f"Payload length: {len(payload)} bytes")
    if not payload:
        print("Empty payload.")
    else:
        print("Hex:")
        print(payload.hex(" ").upper())
        print("Text:")
        print(payload.decode("utf-8", errors="replace"))
    print("=" * 50 + "\n")

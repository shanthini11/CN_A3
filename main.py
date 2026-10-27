"""Main command-line program for the Mini Packet Analyzer."""

from capture import capture_packets, list_interfaces
from parser import parse_packet
from filters import filter_packets
from display import show_summary, show_details


def ask_and_filter(packets):
    print("\nEnter a value to filter by, or press Enter to skip that filter.")
    protocol = input("Protocol (TCP/UDP): ").strip().upper()
    if protocol not in ("", "TCP", "UDP"):
        print("Protocol must be TCP, UDP, or blank. No filter applied.")
        protocol = ""

    source_ip = input("Source IP: ").strip()
    destination_ip = input("Destination IP: ").strip()
    source_port = input("Source port: ").strip()
    destination_port = input("Destination port: ").strip()

    results = filter_packets(
        packets,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
    )
    show_summary(results)


def inspect_packet(packets):
    try:
        number = int(input("Enter the packet number to inspect: ").strip())
    except ValueError:
        print("Please enter a whole number.")
        return

    for packet in packets:
        if packet["number"] == number:
            show_details(packet)
            return
    print("Packet number not found.")


def main():
    print("=" * 45)
    print("       MINI PACKET ANALYZER")
    print("=" * 45)
    print("Capture only on networks you own or are allowed to analyze.\n")

    interfaces = list_interfaces()
    if interfaces:
        print("Available network interfaces:")
        for name in interfaces:
            print("-", name)

    default_interface = "en0" if "en0" in interfaces else (interfaces[0] if interfaces else "en0")
    interface = input(f"Interface [{default_interface}]: ").strip() or default_interface

    try:
        packet_count = int(input("Maximum packets to capture [50]: ").strip() or "50")
        duration = int(input("Capture duration in seconds [15]: ").strip() or "15")
        if packet_count <= 0 or duration <= 0:
            print("Packet count and duration must be greater than zero.")
            return
    except ValueError:
        print("Please enter whole numbers for the packet count and duration.")
        return

    print(f"\nCapturing on {interface} for up to {duration} seconds (or {packet_count} packets).")
    print("Generate some ordinary network activity while capture is running.\n")

    try:
        captured = capture_packets(interface, packet_count, duration)
    except Exception as error:
        print("Could not capture packets.")
        print("Check the interface name, Scapy installation, and capture permissions.")
        print("Error:", error)
        print("On macOS, try: sudo .venv/bin/python main.py")
        return

    packets = []
    for item in captured:
        packet = parse_packet(item["raw"], len(packets) + 1, item["time"])
        if packet is not None:
            packets.append(packet)

    print(f"\nCaptured {len(captured)} raw frames; parsed {len(packets)} IPv4 packets.")
    if not packets:
        print("No IPv4 packets were found. Try another interface or capture again while browsing.")

    while True:
        print("\nMENU")
        print("1. Show all packets")
        print("2. Filter packets")
        print("3. Inspect one packet")
        print("4. Exit")
        choice = input("Choose 1-4: ").strip()

        if choice == "1":
            show_summary(packets)
        elif choice == "2":
            ask_and_filter(packets)
        elif choice == "3":
            inspect_packet(packets)
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Please choose 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()

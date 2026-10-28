"""Main command-line program for the Mini Packet Analyzer."""

from capture import capture_packets, list_interfaces, default_interface
from parser import parse_packet
from filters import filter_packets
from display import show_summary, show_details


def choose_interface():
    """List interfaces by number and return the chosen interface name, or None."""
    interfaces = list_interfaces()
    names = [item["name"] for item in interfaces]
    default = default_interface()
    if default not in names:
        default = "en0" if "en0" in names else (names[0] if names else None)

    if interfaces:
        print("Available network interfaces:")
        for index, item in enumerate(interfaces, start=1):
            details = " - ".join(text for text in (item["description"], item["ip"])
                                 if text and text != item["name"])
            marker = "  (default)" if item["name"] == default else ""
            print(f"{index:>2}. {item['name']}" + (f"  [{details}]" if details else "") + marker)
    else:
        print("No network interfaces were found. Check the Scapy/Npcap installation.")

    prompt = f"Interface number or name [{default}]: " if default else "Interface name: "
    choice = input(prompt).strip()
    if not choice:
        if default is None:
            print("No interface selected.")
        return default
    if choice.isdigit():
        if 1 <= int(choice) <= len(interfaces):
            return names[int(choice) - 1]
        print(f"Please choose a number from 1 to {len(interfaces)}.")
        return None
    return choice


def ask_and_filter(packets):
    print("\nEnter a value to filter by, or press Enter to skip that filter.")
    protocol = input("Protocol (TCP/UDP): ").strip()
    source_ip = input("Source IP: ").strip()
    destination_ip = input("Destination IP: ").strip()
    source_port = input("Source port: ").strip()
    destination_port = input("Destination port: ").strip()

    try:
        results = filter_packets(
            packets,
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
        )
    except ValueError as error:
        print(f"Invalid filter: {error} No filter applied.")
        return
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

    interface = choose_interface()
    if interface is None:
        return

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
        print("On Windows, install Npcap (https://npcap.com) and, if needed, run the terminal as Administrator.")
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

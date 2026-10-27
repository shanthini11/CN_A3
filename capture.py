"""Capture raw packet bytes. Header parsing is done separately in parser.py."""

from datetime import datetime
from scapy.all import sniff, get_if_list


def list_interfaces():
    """Return network interface names available to Scapy."""
    return get_if_list()


def capture_packets(interface, packet_count=50, duration=15):
    """Capture raw packet bytes for at most duration seconds or packet_count packets."""
    captured = []

    def save_packet(packet):
        raw_bytes = bytes(packet)  # Save raw bytes; do not use Scapy to decode headers.
        captured.append({
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "raw": raw_bytes,
            "size": len(raw_bytes),
        })

    sniff(
        iface=interface,
        count=packet_count,
        timeout=duration,
        prn=save_packet,
        store=False,
    )
    return captured

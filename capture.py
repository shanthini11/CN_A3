"""Capture raw packet bytes. Header parsing is done separately in parser.py."""

from datetime import datetime
from scapy.all import sniff, conf, get_working_ifaces


def list_interfaces():
    """Return the network interfaces available to Scapy.

    Each item is a dictionary with a short name to type (for example "Wi-Fi"
    on Windows or "en0" on macOS), a description and the interface's IPv4
    address. On Windows the short name replaces long names such as
    \\Device\\NPF_{GUID}.
    """
    interfaces = []
    for interface in get_working_ifaces():
        interfaces.append({
            "name": interface.name,
            "description": interface.description or "",
            "ip": interface.ip or "",
        })
    return interfaces


def default_interface():
    """Return the name of the interface Scapy would use by default, or None."""
    interface = conf.iface
    return getattr(interface, "name", None) or (str(interface) if interface else None)


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

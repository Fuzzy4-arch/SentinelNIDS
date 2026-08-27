from scapy.all import sniff


def start_capture(packet_handler, count=10):
    print(f"Capturing {count} packets...")
    packets = sniff(count=count)
    packet_handler(packets)

from scapy.all import sniff


def capture_packets(count=10):
    print(f"Capturing {count} packets...")
    return sniff(count=count)
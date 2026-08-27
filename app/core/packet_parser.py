from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP


@dataclass
class NetworkPacket:
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None
    destination_port: int | None


def parse_packet(packet) -> NetworkPacket | None:
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    protocol = "OTHER"
    source_port = None
    destination_port = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    return NetworkPacket(
        source_ip=ip_layer.src,
        destination_ip=ip_layer.dst,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
    )
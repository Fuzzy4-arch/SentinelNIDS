from scapy.all import IP, TCP


def simulate_port_scan():
    packets = []

    ports = [21, 22, 23, 80, 443]

    for i, port in enumerate(ports):
        packet = (
            IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=50000 + i, dport=port)
        )
        packets.append(packet)

    return packets
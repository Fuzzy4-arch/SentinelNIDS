from scapy.layers.inet import IP, TCP

from app.core.packet_parser import parse_packet


def test_parse_tcp_packet():
    packet = (
        IP(src="10.0.0.5", dst="10.0.0.10")
        / TCP(sport=12345, dport=22)
    )

    result = parse_packet(packet)

    assert result is not None
    assert result.source_ip == "10.0.0.5"
    assert result.destination_ip == "10.0.0.10"
    assert result.protocol == "TCP"
    assert result.source_port == 12345
    assert result.destination_port == 22


def test_packet_without_ip_is_ignored():
    from scapy.layers.inet import TCP

    packet = TCP(sport=12345, dport=80)

    result = parse_packet(packet)

    assert result is None

from app.detectors.rules import detect_port_scan


def test_port_scan_detection():
    packets = []

    ports = [21, 22, 23, 80, 443]

    for port in ports:
        packet = (
            IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=50000, dport=port)
        )

        packets.append(parse_packet(packet))

    alerts = detect_port_scan(packets)

    assert len(alerts) == 1
    assert alerts[0].rule == "PORT_SCAN"
    assert alerts[0].source_ip == "10.0.0.5"
    assert alerts[0].ports_contacted == 5
    assert alerts[0].severity == "HIGH"
from app.core.risk import calculate_risk, risk_level


def test_medium_risk():
    score = calculate_risk(5)

    assert score == 60
    assert risk_level(score) == "MEDIUM"


def test_high_risk():
    score = calculate_risk(10)

    assert score == 80
    assert risk_level(score) == "HIGH"


def test_critical_risk():
    score = calculate_risk(20)

    assert score == 95
    assert risk_level(score) == "CRITICAL"


def test_low_risk():
    score = calculate_risk(2)

    assert score == 20
    assert risk_level(score) == "LOW"
from app.detectors.rules import detect_ssh_burst


def test_ssh_burst_detection():
    packets = []

    for i in range(3):
        packet = (
            IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=50000 + i, dport=22)
        )

        packets.append(parse_packet(packet))

    alerts = detect_ssh_burst(packets)

    assert len(alerts) == 1
    assert alerts[0].rule == "SSH_CONNECTION_BURST"
    assert alerts[0].source_ip == "10.0.0.5"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].risk_score == 80
    assert alerts[0].risk_level == "HIGH"
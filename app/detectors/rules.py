from collections import defaultdict
from dataclasses import dataclass

from app.core.packet_parser import NetworkPacket
from app.core.risk import calculate_risk, risk_level


@dataclass
class NetworkAlert:
    rule: str
    source_ip: str
    ports_contacted: int
    severity: str
    risk_score: int
    risk_level: str
    description: str


def detect_port_scan(
    packets: list[NetworkPacket],
    threshold: int = 5,
) -> list[NetworkAlert]:

    ports_by_ip = defaultdict(set)
    alerts = []

    for packet in packets:

        if packet.destination_port is None:
            continue

        ports_by_ip[packet.source_ip].add(packet.destination_port)

        port_count = len(ports_by_ip[packet.source_ip])

        if port_count == threshold:

            score = calculate_risk(port_count)

            alerts.append(
                NetworkAlert(
                    rule="PORT_SCAN",
                    source_ip=packet.source_ip,
                    ports_contacted=port_count,
                    severity="HIGH",
                    risk_score=score,
                    risk_level=risk_level(score),
                    description="Multiple destination ports contacted by one source IP",
                )
            )

    return alerts
def detect_ssh_burst(
    packets: list[NetworkPacket],
    threshold: int = 3,
) -> list[NetworkAlert]:

    ssh_connections = defaultdict(int)
    alerts = []

    for packet in packets:
        if packet.protocol != "TCP" or packet.destination_port != 22:
            continue

        ssh_connections[packet.source_ip] += 1

        if ssh_connections[packet.source_ip] == threshold:
            score = calculate_risk(10)

            alerts.append(
                NetworkAlert(
                    rule="SSH_CONNECTION_BURST",
                    source_ip=packet.source_ip,
                    ports_contacted=threshold,
                    severity="HIGH",
                    risk_score=score,
                    risk_level=risk_level(score),
                    description="Multiple SSH connections detected from one source IP",
                )
            )

    return alerts


def detect_ssh_burst(
    packets: list[NetworkPacket],
    threshold: int = 3,
) -> list[NetworkAlert]:

    ssh_connections = defaultdict(int)
    alerts = []

    for packet in packets:
        if packet.protocol != "TCP" or packet.destination_port != 22:
            continue

        ssh_connections[packet.source_ip] += 1

        if ssh_connections[packet.source_ip] == threshold:
            score = calculate_risk(10)

            alerts.append(
                NetworkAlert(
                    rule="SSH_CONNECTION_BURST",
                    source_ip=packet.source_ip,
                    ports_contacted=threshold,
                    severity="HIGH",
                    risk_score=score,
                    risk_level=risk_level(score),
                    description="Multiple SSH connections detected from one source IP",
                )
            )

    return alerts

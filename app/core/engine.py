from app.detectors.rules import detect_port_scan, detect_ssh_burst
from app.core.risk import calculate_risk, risk_level
from app.storage.database import save_alert


def analyze_packets(packets):
    alerts = []

    for alert in detect_port_scan(packets) + detect_ssh_burst(packets):
        score = calculate_risk(alert.ports_contacted)

        alert = alert.__class__(
            rule=alert.rule,
            source_ip=alert.source_ip,
            ports_contacted=alert.ports_contacted,
            severity=alert.severity,
            description=alert.description,
            risk_score=score,
            risk_level=risk_level(score),
        )

        save_alert(alert)
        alerts.append(alert)

    return alerts
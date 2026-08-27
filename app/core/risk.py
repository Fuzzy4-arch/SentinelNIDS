def calculate_risk(ports_contacted: int) -> int:
    if ports_contacted >= 20:
        return 95

    if ports_contacted >= 10:
        return 80

    if ports_contacted >= 5:
        return 60

    return 20


def risk_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"
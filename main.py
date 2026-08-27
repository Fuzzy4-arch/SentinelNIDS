from app.core.capture import capture_packets
from app.core.packet_parser import parse_packet
from app.core.engine import analyze_packets
from app.storage.database import init_db


def main():
    print("=" * 40)
    print("        SENTINELNIDS")
    print("   NETWORK INTRUSION DETECTION")
    print("=" * 40)

    init_db()

    raw_packets = capture_packets(count=10)

    packets = []

    for packet in raw_packets:
        parsed = parse_packet(packet)

        if parsed:
            packets.append(parsed)

    print(f"\nPackets parsed: {len(packets)}")

    alerts = analyze_packets(packets)

    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert.risk_level}] "
            f"{alert.rule} | "
            f"{alert.source_ip} | "
            f"score={alert.risk_score}"
        )


if __name__ == "__main__":
    main()
from app.core.simulator import simulate_port_scan
from app.core.packet_parser import parse_packet
from app.core.engine import analyze_packets
from app.storage.database import init_db, save_alert


def main():
    print("=" * 40)
    print("        SENTINELNIDS")
    print("   NETWORK INTRUSION DETECTION")
    print("=" * 40)

    init_db()

    print("Simulating port scan...")
    raw_packets = simulate_port_scan()

    packets = [parse_packet(packet) for packet in raw_packets]
    packets = [packet for packet in packets if packet is not None]

    alerts = analyze_packets(packets)

    print(f"\nPackets parsed: {len(packets)}")
    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        save_alert(alert)

        print(
            f"[{alert.risk_level}] "
            f"{alert.rule} | "
            f"{alert.source_ip} | "
            f"risk={alert.risk_score}"
        )


if __name__ == "__main__":
    main()
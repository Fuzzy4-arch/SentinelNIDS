from app.core.simulator import simulate_port_scan, simulate_ssh_burst
from app.core.packet_parser import parse_packet
from app.core.engine import analyze_packets
from app.storage.database import init_db, save_alert


def process_packets(raw_packets):
    packets = [parse_packet(packet) for packet in raw_packets]
    packets = [packet for packet in packets if packet is not None]

    alerts = analyze_packets(packets)

    for alert in alerts:
        save_alert(alert)
        print(
            f"[{alert.risk_level}] "
            f"{alert.rule} | "
            f"{alert.source_ip} | "
            f"risk={alert.risk_score}"
        )

    return packets, alerts


def main():
    print("=" * 40)
    print("        SENTINELNIDS")
    print("   NETWORK INTRUSION DETECTION")
    print("=" * 40)

    init_db()

    print("\nSimulating port scan...")
    packets1, alerts1 = process_packets(simulate_port_scan())

    print("\nSimulating SSH burst...")
    packets2, alerts2 = process_packets(simulate_ssh_burst())

    print(f"\nPackets parsed: {len(packets1) + len(packets2)}")
    print(f"Alerts detected: {len(alerts1) + len(alerts2)}")


if __name__ == "__main__":
    main()
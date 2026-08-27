import sqlite3
from pathlib import Path

DB_PATH = Path("sentinelnids.db")


def init_db():
    connection = sqlite3.connect(DB_PATH)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            ports_contacted INTEGER NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            description TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_alert(alert):
    connection = sqlite3.connect(DB_PATH)

    connection.execute(
        """
        INSERT INTO alerts (
            rule,
            source_ip,
            ports_contacted,
            severity,
            risk_score,
            risk_level,
            description
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.rule,
            alert.source_ip,
            alert.ports_contacted,
            alert.severity,
            alert.risk_score,
            alert.risk_level,
            alert.description,
        ),
    )

    connection.commit()
    connection.close()


def get_alerts():
    connection = sqlite3.connect(DB_PATH)

    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]
from fastapi import FastAPI, HTTPException

from app.storage.database import init_db, get_alerts

app = FastAPI(
    title="SentinelNIDS API",
    description="Network Intrusion Detection System API",
    version="1.0.0",
)

init_db()


@app.get("/")
def root():
    return {
        "name": "SentinelNIDS",
        "status": "online",
    }


@app.get("/alerts")
def alerts():
    return get_alerts()


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    alerts_data = get_alerts()

    for alert in alerts_data:
        if alert["id"] == alert_id:
            return alert

    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/stats")
def stats():
    alerts_data = get_alerts()

    return {
        "total_alerts": len(alerts_data),
        "high_severity": sum(
            1 for alert in alerts_data
            if alert["severity"] == "HIGH"
        ),
        "critical_risk": sum(
            1 for alert in alerts_data
            if alert["risk_level"] == "CRITICAL"
        ),
        "port_scans": sum(
            1 for alert in alerts_data
            if alert["rule"] == "PORT_SCAN"
        ),
    }
from fastapi import FastAPI

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
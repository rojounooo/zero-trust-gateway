import requests
import time

INGEST_URL = "http://<GATEWAY_IP>:<INGESTION_PORT>/event"


def sendEvent(
    phase: str,
    eventType: str,
    ip: str,
    userId: str | None,
    userRole: str | None,
    path: str,
    method: str,
    status: int,
    attackType: str | None = None,
) -> None:

    event = {
        "timestamp": time.time(),
        "phase": phase,
        "event_type": eventType,
        "attack_type": attackType,
        "ip": ip,
        "user_id": userId,
        "user_role": userRole,
        "path": path,
        "method": method,
        "status": status,
    }

    try:
        requests.post(INGEST_URL, json=event, timeout=1)
    except:
        pass
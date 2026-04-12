from typing import Optional

def validateEvent(data: dict) -> dict:
    return {
        "timestamp": data.get("timestamp"),
        "phase": data.get("phase"),
        "event_type": data.get("event_type"),
        "attack_type": data.get("attack_type"),
        "ip": data.get("ip"),
        "user_id": data.get("user_id"),
        "user_role": data.get("user_role"),
        "path": data.get("path"),
        "method": data.get("method"),
        "status": data.get("status"),
    }
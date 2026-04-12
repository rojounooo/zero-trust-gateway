import time

FAILED_LOGINS = {}

WINDOW = 60
THRESHOLD = 5
ROLE_PATHS = {"doctor", "nurse", "pharmacist", "admin"}


def _cleanup(ip: str, now: float) -> None:
    if ip not in FAILED_LOGINS:
        return

    FAILED_LOGINS[ip] = [t for t in FAILED_LOGINS[ip] if now - t <= WINDOW]


def _bruteForce(event: dict) -> list:
    alerts = []

    ip = event.get("ip")
    status = event.get("status")
    path = event.get("path", "")
    now = time.time()

    if not ip:
        return alerts

    if "token" not in path:
        return alerts

    if status not in [401, 403]:
        return alerts

    FAILED_LOGINS.setdefault(ip, [])
    FAILED_LOGINS[ip].append(now)

    _cleanup(ip, now)

    if len(FAILED_LOGINS[ip]) >= THRESHOLD:
        alerts.append({
            "timestamp": now,
            "ip": ip,
            "type": "brute_force",
            "severity": "HIGH",
            "message": "Multiple failed login attempts"
        })

    return alerts


def _offShift(event: dict) -> list:
    alerts = []

    if event.get("attack_type") != "off_shift":
        return alerts

    alerts.append({
        "timestamp": time.time(),
        "ip": event.get("ip"),
        "type": "off_shift",
        "severity": "MEDIUM",
        "message": "Off-shift access attempt"
    })

    return alerts


def _roleConfusion(event: dict) -> list:
    alerts = []

    path = event.get("path", "")
    userRole = event.get("user_role")

    parts = path.strip("/").split("/")
    if not parts:
        return alerts

    pathRole = parts[0]

    if pathRole not in ROLE_PATHS:
        return alerts

    if not userRole:
        return alerts

    if pathRole != userRole:
        alerts.append({
            "timestamp": time.time(),
            "ip": event.get("ip"),
            "type": "role_confusion",
            "severity": "MEDIUM",
            "message": f"{userRole} accessing {pathRole}"
        })

    return alerts


def evaluateRules(event: dict) -> list:
    alerts = []

    alerts += _bruteForce(event)
    alerts += _offShift(event)
    alerts += _roleConfusion(event)

    return alerts
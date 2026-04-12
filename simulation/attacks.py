"""
Explanation:
    Attack simulation helpers used by phase2.py and phase3.py.

    This file does NOT send events to the ingestion endpoint.
    It only performs attack actions and returns event dictionaries.
"""

import asyncio
import httpx
import logging
import os

from dotenv import load_dotenv

from keycloak import get_token
from helpers import make_request
from ip_config import get_attacker_ip, get_off_shift_ip, get_on_shift_ip

load_dotenv()

KEYCLOAK_URL = os.environ["KEYCLOAK_URL"]
KEYCLOAK_REALM = os.environ["KEYCLOAK_REALM"]
CLIENT_ID = os.environ["KEYCLOAK_CLIENT_ID"]
CLIENT_SECRET = os.environ["KEYCLOAK_CLIENT_SECRET"]

log = logging.getLogger(__name__)

PASSWORD_LIST = [
    "password123",
    "12345678",
    "qwerty",
    "letmein",
    "admin",
    "welcome",
    "monkey",
    "abc123",
]

ROLE_PATHS = {
    "doctor": "/doctor/dashboard",
    "nurse": "/nurse/dashboard",
    "pharmacist": "/pharmacist/dashboard",
    "admin": "/admin/dashboard",
}


async def passwordBruteForce(username: str, passwordList: list[str], xff: str) -> list[dict]:
    """
    Perform brute-force login attempts and return one event per attempt.
    """
    tokenUrl = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    events = []

    log.info(f"[BRUTE FORCE] Target: {username} xff={xff}")

    async with httpx.AsyncClient(timeout=5) as client:
        for password in passwordList:
            try:
                response = await client.post(
                    tokenUrl,
                    data={
                        "grant_type": "password",
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                        "username": username,
                        "password": password,
                    },
                    headers={
                        "X-Forwarded-For": xff
                    }
                )

                events.append({
                    "ip": xff,
                    "user_id": username,
                    "user_role": None,
                    "path": "/token",
                    "method": "POST",
                    "status": response.status_code,
                    "attack_type": "brute_force",
                })

            except httpx.HTTPError:
                events.append({
                    "ip": xff,
                    "user_id": username,
                    "user_role": None,
                    "path": "/token",
                    "method": "POST",
                    "status": 0,
                    "attack_type": "brute_force",
                })

    return events


async def offShiftAccess(credentials: dict) -> list[dict]:
    """
    Perform one off-shift access attempt and return one event.
    """
    result = get_off_shift_ip(credentials)
    if not result:
        log.warning("[OFF SHIFT] No off-shift users found")
        return []

    xff, username, password, role = result

    log.info(f"[OFF SHIFT] Target: {username} ({role}) xff={xff}")

    token = await get_token(username, password)
    if not token:
        log.warning(f"[OFF SHIFT] Could not get token for {username}")
        return []

    path = f"/{role}/dashboard"
    status = await make_request(token, path, xff)

    return [{
        "ip": xff,
        "user_id": username,
        "user_role": role,
        "path": path,
        "method": "GET",
        "status": status,
        "attack_type": "off_shift",
    }]


async def roleConfusion(credentials: dict) -> list[dict]:
    """
    Perform cross-role access attempts and return one event per attempt.
    """
    result = get_on_shift_ip(credentials)
    if not result:
        log.warning("[ROLE CONFUSION] No on-shift users found")
        return []

    _, username, password, role = result
    xff = get_attacker_ip()

    log.info(f"[ROLE CONFUSION] Attacker: {username} ({role}) xff={xff}")

    token = await get_token(username, password)
    if not token:
        log.warning(f"[ROLE CONFUSION] Could not get token for {username}")
        return []

    events = []

    for targetRole, path in ROLE_PATHS.items():
        if targetRole == role:
            continue

        status = await make_request(token, path, xff)

        events.append({
            "ip": xff,
            "user_id": username,
            "user_role": role,
            "path": path,
            "method": "GET",
            "status": status,
            "attack_type": "role_confusion",
        })

        await asyncio.sleep(1)

    return events
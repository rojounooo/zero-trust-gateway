"""
Explanation:
    Shared utility functions used by all other files in the simulation.
    Handles:
    - loading credentials and patient names
    - shift logic (including overnight shifts)
    - filtering users by shift status
    - building realistic role-based paths
    - auto-generating consistent IP addresses per user (for XFF simulation)
"""

# --------------------------------------------------
import httpx
import json
import os
import random
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv


load_dotenv()

CREDENTIALS_FILE   = os.environ["CREDENTIALS_FILE"]
PATIENT_NAMES_FILE = os.environ["PATIENT_NAMES_FILE"]
LOG_FILE           = os.environ["LOG_FILE"]
GATEWAY_URL = os.environ["GATEWAY_URL"]

# --------------------------------------------------
# Load shift definitions

with open(os.environ["SHIFTS"]) as f:
    SHIFTS: dict = json.load(f)

# --------------------------------------------------
# Data loading

def load_credentials() -> dict:
    with open(CREDENTIALS_FILE) as f:
        return json.load(f)

def load_patient_names() -> list:
    return Path(PATIENT_NAMES_FILE).read_text().strip().splitlines()

# --------------------------------------------------
# Shift logic

def is_on_shift(username: str) -> bool:
    """Check if a user is currently on shift using local shift data."""
    shift = SHIFTS.get(username)
    if not shift:
        return False

    now  = datetime.now()
    day  = now.strftime("%A").lower()
    hour = now.hour

    if shift["start"] <= shift["end"]:
        # Normal shift (e.g. 07:00–19:00)
        return day in shift["days"] and shift["start"] <= hour < shift["end"]
    else:
        # Overnight shift (e.g. 19:00–07:00)
        if day in shift["days"] and hour >= shift["start"]:
            return True

        yesterday_idx = (now.weekday() - 1) % 7
        days_map = ["monday","tuesday","wednesday","thursday","friday","saturday","sunday"]
        yesterday = days_map[yesterday_idx]

        return yesterday in shift["days"] and hour < shift["end"]


# --------------------------------------------------
# User filtering

def get_on_shift_users(credentials: dict) -> list:
    """Return list of (username, password, role) for users currently on shift."""
    on_shift = []
    for role, users in credentials.items():
        for user in users:
            if is_on_shift(user["username"]):
                on_shift.append((user["username"], user["password"], role))
    return on_shift

def get_off_shift_users(credentials: dict) -> list:
    """Return list of (username, password, role) for users currently off shift."""
    off_shift = []
    for role, users in credentials.items():
        if role == "test":
            continue  # exclude test accounts
        for user in users:
            if not is_on_shift(user["username"]):
                off_shift.append((user["username"], user["password"], role))
    return off_shift

# --------------------------------------------------
# Time helpers

def night_mode() -> bool:
    """Returns True between 23:00 and 07:00."""
    hour = datetime.now().hour
    return hour >= 23 or hour < 7

# --------------------------------------------------
# Role-based paths

def role_paths(role: str, patient_names: list) -> list:
    """Return a list of paths a user with this role would realistically visit."""
    name = random.choice(patient_names)

    paths = {
        "doctor":     [f"/{role}/dashboard", f"/{role}/patient?name={name}"],
        "nurse":      [f"/{role}/dashboard", f"/{role}/patient?name={name}"],
        "pharmacist": [f"/{role}/dashboard", f"/{role}/patient?name={name}"],
        "admin":      [f"/{role}/dashboard"],
    }

    return paths.get(role, [f"/{role}/dashboard"])

# --------------------------------------------------
# Request helper

async def make_request(token: str, path: str, xff: str = None) -> int:
    """Make an authenticated GET request to the gateway. Returns status code."""
    url = f"{GATEWAY_URL}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    if xff:
        headers["X-Forwarded-For"] = xff
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            return resp.status_code
    except httpx.HTTPError:
        return 0

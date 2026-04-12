import asyncio
import logging
import random

from dotenv import load_dotenv

from keycloak import get_token
from helpers import (
    load_credentials,
    load_patient_names,
    make_request,
    night_mode,
    role_paths,
)
from ip_config import get_on_shift_ip
from utils import sendEvent

load_dotenv()

log = logging.getLogger(__name__)


async def normalTrafficSession(credentials: dict, patientNames: list, phase: str) -> None:
    result = get_on_shift_ip(credentials)
    if not result:
        log.info("[PHASE 1] No on-shift users — skipping session")
        return

    xff, username, password, role = result

    token = await get_token(username, password)
    if not token:
        log.warning(f"[PHASE 1] Could not get token for {username}")
        return

    paths = role_paths(role, patientNames)

    for path in paths:
        status = await make_request(token, path, xff)

        sendEvent(
            phase=phase,
            eventType="normal",
            ip=xff,
            userId=username,
            userRole=role,
            path=path,
            method="GET",
            status=status,
            attackType=None,
        )

        log.info(f"[PHASE 1] {username} ({role}) xff={xff} GET {path} -> {status}")
        await asyncio.sleep(random.uniform(2, 8))


async def run(durationSeconds: int, phase: str = "phase1") -> None:
    log.info(f"[PHASE 1] Starting baseline traffic for {durationSeconds}s")

    credentials = load_credentials()
    patientNames = load_patient_names()

    loop = asyncio.get_running_loop()
    endTime = loop.time() + durationSeconds

    while loop.time() < endTime:
        await normalTrafficSession(credentials, patientNames, phase)

        delay = random.uniform(120, 300) if night_mode() else random.uniform(30, 90)
        await asyncio.sleep(delay)

    log.info("[PHASE 1] Complete")
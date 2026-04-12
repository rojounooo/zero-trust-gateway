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
from ip_config import get_attacker_ip, get_on_shift_ip
from attacks import (
    PASSWORD_LIST,
    offShiftAccess,
    passwordBruteForce,
    roleConfusion,
)
from utils import sendEvent

load_dotenv()

log = logging.getLogger(__name__)


async def normalTrafficSession(credentials: dict, patientNames: list, phase: str) -> None:
    result = get_on_shift_ip(credentials)
    if not result:
        return

    xff, username, password, role = result

    token = await get_token(username, password)
    if not token:
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

        log.info(f"[PHASE 3] {username} ({role}) xff={xff} GET {path} -> {status}")
        await asyncio.sleep(random.uniform(2, 8))


async def normalTrafficLoop(credentials: dict, patientNames: list, endTime: float, phase: str) -> None:
    loop = asyncio.get_running_loop()

    while loop.time() < endTime:
        await normalTrafficSession(credentials, patientNames, phase)
        delay = random.uniform(120, 300) if night_mode() else random.uniform(30, 90)
        await asyncio.sleep(delay)


async def randomAttack(credentials: dict, phase: str) -> None:
    attackName = random.choice(["brute_force", "off_shift", "role_confusion"])
    log.info(f"[PHASE 3] Injecting attack: {attackName}")

    if attackName == "brute_force":
        users = credentials.get("test", [])

        if not users:
            log.warning("[PHASE 3] No test users available for brute force")
            return

        target = random.choice(users)
        xff = get_attacker_ip()

        events = await passwordBruteForce(target["username"], PASSWORD_LIST, xff)

    elif attackName == "off_shift":
        events = await offShiftAccess(credentials)

    else:
        events = await roleConfusion(credentials)

    for event in events:
        sendEvent(
            phase=phase,
            eventType="attack",
            ip=event["ip"],
            userId=event["user_id"],
            userRole=event["user_role"],
            path=event["path"],
            method=event["method"],
            status=event["status"],
            attackType=event["attack_type"],
        )


async def attackInjector(credentials: dict, endTime: float, phase: str) -> None:
    loop = asyncio.get_running_loop()

    while loop.time() < endTime:
        delay = random.uniform(300, 900)
        await asyncio.sleep(delay)

        if loop.time() >= endTime:
            break

        await randomAttack(credentials, phase)


async def run(durationSeconds: int, phase: str = "phase3") -> None:
    log.info(f"[PHASE 3] Starting mixed load for {durationSeconds}s")

    credentials = load_credentials()
    patientNames = load_patient_names()

    loop = asyncio.get_running_loop()
    endTime = loop.time() + durationSeconds

    trafficTask = asyncio.create_task(
        normalTrafficLoop(credentials, patientNames, endTime, phase)
    )

    attackTask = asyncio.create_task(
        attackInjector(credentials, endTime, phase)
    )

    try:
        await asyncio.gather(trafficTask, attackTask)
    finally:
        for task in (trafficTask, attackTask):
            task.cancel()

        for task in (trafficTask, attackTask):
            try:
                await task
            except asyncio.CancelledError:
                pass

    log.info("[PHASE 3] Complete")
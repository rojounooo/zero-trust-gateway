import asyncio
import logging
import random

from dotenv import load_dotenv

from helpers import load_credentials
from attacks import (
    PASSWORD_LIST,
    offShiftAccess,
    passwordBruteForce,
    roleConfusion,
)
from ip_config import get_attacker_ip
from utils import sendEvent

load_dotenv()

log = logging.getLogger(__name__)


async def runBruteForce(credentials: dict, phase: str) -> None:
    users = credentials.get("test", [])

    if not users:
        log.warning("[PHASE 2] No test users available for brute force")
        return

    target = random.choice(users)
    xff = get_attacker_ip()

    events = await passwordBruteForce(target["username"], PASSWORD_LIST, xff)

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


async def runOffShift(credentials: dict, phase: str) -> None:
    events = await offShiftAccess(credentials)

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


async def runRoleConfusion(credentials: dict, phase: str) -> None:
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


async def run(durationSeconds: int, phase: str = "phase2") -> None:
    """
    Structured attacks only.
    """
    log.info(f"[PHASE 2] Starting structured attacks for {durationSeconds}s")

    credentials = load_credentials()

    loop = asyncio.get_running_loop()
    endTime = loop.time() + durationSeconds

    attackOrder = [
        "brute_force",
        "off_shift",
        "role_confusion",
    ]

    attackIndex = 0

    while loop.time() < endTime:
        attackName = attackOrder[attackIndex % len(attackOrder)]

        if attackName == "brute_force":
            log.info("[PHASE 2] Running brute force")
            await runBruteForce(credentials, phase)

        elif attackName == "off_shift":
            log.info("[PHASE 2] Running off-shift access")
            await runOffShift(credentials, phase)

        elif attackName == "role_confusion":
            log.info("[PHASE 2] Running role confusion")
            await runRoleConfusion(credentials, phase)

        attackIndex += 1
        await asyncio.sleep(30)

    log.info("[PHASE 2] Complete")
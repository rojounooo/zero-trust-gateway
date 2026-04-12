import asyncio
import logging
import sys
from datetime import datetime

import phase1
import phase2
import phase3

LOG_FILE = "experiment.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

log = logging.getLogger(__name__)

PHASE_DURATION = 3600


def separator(label: str) -> None:
    log.info("=" * 60)
    log.info(f"  {label}")
    log.info(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info("=" * 60)


async def runPhase(name: str, phaseFunc, phaseTag: str) -> None:
    separator(name)

    task = asyncio.create_task(phaseFunc(PHASE_DURATION, phaseTag))

    try:
        await task
    except Exception as e:
        log.error(f"[{name}] error: {e}")
    finally:
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


async def main() -> None:
    separator("EXPERIMENT START")
    log.info(f"Phase duration: {PHASE_DURATION}s per phase")
    log.info(f"Total duration: ~{(PHASE_DURATION * 3) // 60} minutes")

    await runPhase("PHASE 1 — Baseline Traffic", phase1.run, "phase1")
    await runPhase("PHASE 2 — Structured Attacks", phase2.run, "phase2")
    await runPhase("PHASE 3 — Mixed Load", phase3.run, "phase3")

    separator("EXPERIMENT COMPLETE")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())
import json
import os
import time

from rules import evaluateRules

EVENTS_FILE = "/home/<USERNAME>/logs/events.log"
ALERT_FILE = "/home/<USERNAME>/logs/alerts.log"
BLOCKLIST_FILE = "/home/<USERNAME>/logs/blocklist.txt"


def writeAlert(alert: dict) -> None:
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")


def addBlock(ip: str) -> None:
    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            blocked = set(f.read().splitlines())
    except FileNotFoundError:
        blocked = set()

    if ip not in blocked:
        with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
            f.write(ip + "\n")


def isBlocked(ip: str) -> bool:
    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            return ip in f.read().splitlines()
    except FileNotFoundError:
        return False


def waitForFile(filePath: str) -> None:
    while not os.path.exists(filePath):
        time.sleep(0.2)


def follow(file):
    file.seek(0, os.SEEK_END)

    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


def main() -> None:
    print("[*] Detector started")
    print(f"[*] Waiting for {EVENTS_FILE}")

    waitForFile(EVENTS_FILE)

    with open(EVENTS_FILE, "r", encoding="utf-8") as f:
        for line in follow(f):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") not in ["normal", "attack"]:
                continue

            ip = event.get("ip")
            if not ip:
                continue

            if isBlocked(ip):
                continue

            alerts = evaluateRules(event)

            for alert in alerts:
                print(f"[ALERT] {alert}")
                writeAlert(alert)

                if alert.get("severity") == "HIGH":
                    addBlock(ip)


if __name__ == "__main__":
    main()
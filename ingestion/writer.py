import json
import os
from config import LOG_FILE

def writeEvent(event: dict) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
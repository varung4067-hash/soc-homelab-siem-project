import json
import os

ALERTS_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "alerts.json"
)

def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []

    with open(ALERTS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

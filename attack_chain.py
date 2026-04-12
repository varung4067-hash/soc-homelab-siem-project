from datetime import datetime, timedelta
from siem_engine.attack_classifier import classify_attack


def safe_time(ts):
    """
    Safely parse ISO timestamps.
    """
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.utcnow()


def build_attack_chains(alerts):
    chains = []

    if not alerts:
        return chains

    # Sort alerts safely by timestamp
    alerts = sorted(alerts, key=lambda x: safe_time(x.get("timestamp", "")))

    for i, alert in enumerate(alerts):

        # ----------------------------
        # DEFENSIVE NORMALIZATION
        # ----------------------------
        host = alert.get("host", "UNKNOWN_HOST")
        user = alert.get("user", "Unknown")

        chain = {
            "host": host,
            "user": user,
            "steps": [alert]
        }

        base_time = safe_time(alert.get("timestamp", ""))

        for next_alert in alerts[i + 1:]:

            next_time = safe_time(next_alert.get("timestamp", ""))

            # Stop if outside correlation window
            if next_time - base_time > timedelta(minutes=10):
                break

            if (
                next_alert.get("host", "UNKNOWN_HOST") == host
                and next_alert.get("user", "Unknown") == user
            ):
                chain["steps"].append(next_alert)

        # ----------------------------
        # ATTACK CLASSIFICATION
        # ----------------------------
        if len(chain["steps"]) > 1:
            chain["attack_summary"] = classify_attack(chain)
            chains.append(chain)

    return chains

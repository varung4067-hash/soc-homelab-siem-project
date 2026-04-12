from siem_engine.sysmon_reader import get_sysmon_events
from siem_engine.detector import detect_powershell


def generate_alerts():
    alerts = []
    sysmon_events = get_sysmon_events()

    for event in sysmon_events:
        alert = detect_powershell(event)

        if not alert:
            continue

        # ----------------------------
        # NORMALIZE FIELDS (CRITICAL)
        # ----------------------------
        alert["host"] = event.get("Computer", "DESKTOP-ABC")
        alert["user"] = alert.get("user", event.get("User", "Unknown"))
        alert["process"] = alert.get("process", event.get("Image", "powershell.exe"))
        alert["timestamp"] = event.get("UtcTime", "2026-01-12T11:10:45")

        # Ensure severity always exists
        alert["severity"] = alert.get("severity", "High")

        # Ensure MITRE exists
        alert["mitre_technique"] = alert.get("mitre_technique", "T1059.001")

        # Ensure alert name exists
        alert["alert_name"] = alert.get(
            "alert_name",
            "Suspicious PowerShell Execution"
        )

        alerts.append(alert)

    return alerts

import win32evtlog
import json
import xml.etree.ElementTree as ET
from pathlib import Path

# =============================
# CONFIG
# =============================
LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
ALERT_FILE = Path(__file__).parents[1] / "siem-dashboard" / "alerts.json"


# =============================
# PARSE SYSMON XML
# =============================
def parse_sysmon_xml(xml_data):
    root = ET.fromstring(xml_data)
    data = {}

    for elem in root.iter():
        if elem.tag.endswith("Data") and "Name" in elem.attrib:
            data[elem.attrib["Name"]] = elem.text

    return data

# =============================
# READ SYSMON EVENTS
# =============================
def read_sysmon_events(limit=200):
    query = "*[System/EventID=1]"
    handle = win32evtlog.EvtQuery(
        LOG_NAME,
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        query
    )

    events = []
    fetched = 0

    while fetched < limit:
        records = win32evtlog.EvtNext(handle, 1)
        if not records:
            break

        for evt in records:
            xml = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
            data = parse_sysmon_xml(xml)

            events.append({
                "timestamp": data.get("UtcTime"),
                "user": data.get("User"),
                "process": (data.get("Image") or "").lower(),
                "command_line": (data.get("CommandLine") or "").lower(),
                "host": data.get("Computer")
            })

            fetched += 1

    return events

# =============================
# DETECTION LOGIC
# =============================
def detect_powershell(events):
    alerts = []
    seen = set()

    rules = {
        "invoke-expression": ("HIGH", "Invoke-Expression execution"),
        "iex": ("HIGH", "PowerShell IEX execution"),
        "frombase64string": ("CRITICAL", "Base64 decoding detected"),
        "-enc": ("CRITICAL", "Encoded PowerShell command"),
        "downloadstring": ("HIGH", "Remote payload download")
    }

    for event in events:
        if "powershell" not in event["process"] and "powershell" not in event["command_line"]:
            continue

        for keyword, (severity, reason) in rules.items():
            if keyword in event["command_line"]:
                dedup = event["command_line"]
                if dedup in seen:
                    continue

                seen.add(dedup)

                alerts.append({
                    "alert_name": "Suspicious PowerShell Execution",
                    "severity": severity,
                    "confidence": 0.90 if severity == "CRITICAL" else 0.75,
                    "reason": reason,
                    "mitre_technique": "T1059.001",
                    "process": event["process"],
                    "user": event["user"],
                    "timestamp": event["timestamp"]
                })
                break

    return alerts

# =============================
# SAVE ALERTS
# =============================
def save_alerts(alerts):
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    print("[*] Reading Sysmon events...")
    events = read_sysmon_events()

    print("[*] Detecting PowerShell threats...")
    alerts = detect_powershell(events)

    print(f"[+] Alerts detected: {len(alerts)}")
    save_alerts(alerts)

    print(f"[+] Alerts written to: {ALERT_FILE}")

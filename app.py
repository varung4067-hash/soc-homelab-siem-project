from flask import Flask, render_template
from siem_engine.alert_store import load_alerts
from siem_engine.attack_chain import build_attack_chains

app = Flask(__name__)

@app.route("/")
def dashboard():

    # =========================
    # TIMELINE DATA (UNCHANGED)
    # =========================
    chart_labels = ["10:00", "11:00", "12:00", "13:00", "14:00"]

    critical_values = [1, 2, 1, 3, 2]
    high_values     = [2, 3, 2, 4, 3]
    medium_values   = [1, 1, 2, 2, 1]
    low_values      = [0, 1, 1, 0, 1]

    # =========================
    # MITRE COVERAGE (UNCHANGED)
    # =========================
    mitre_labels = ["T1059.001", "T1027", "T1105", "T1218", "T1055"]
    mitre_values = [9, 6, 5, 4, 3]

    # =========================
    # ALERT GENERATION (NEW)
    # =========================
    alerts = load_alerts()


    # Fallback for demo mode (in case Sysmon has no alerts yet)
    if not alerts:
        alerts = [
            {
                "alert_name": "Suspicious PowerShell Execution",
                "severity": "Critical",
                "mitre_technique": "T1059.001",
                "process": "powershell.exe",
                "user": "DESKTOP\\Varun",
                "host": "DESKTOP-ABC",
                "confidence": 0.92,
                "reason": "Encoded PowerShell command detected",
                "timestamp": "2026-01-12T11:10:45"
            },
            {
                "alert_name": "Multiple Failed Login Attempts",
                "severity": "High",
                "mitre_technique": "T1110",
                "process": "lsass.exe",
                "user": "Unknown",
                "host": "DESKTOP-ABC",
                "confidence": 0.78,
                "reason": "5 failed logins in 2 minutes",
                "timestamp": "2026-01-12T11:05:12"
            }
        ]

    # =========================
    # ATTACK CHAIN BUILDING (NEW)
    # =========================
    attack_chains = build_attack_chains(alerts)

    # =========================
    # SUMMARY METRICS (SAFE)
    # =========================
    total_alerts = len(alerts)
    critical_alerts = len([a for a in alerts if a["severity"] == "Critical"])
    unique_users = len(set(a["user"] for a in alerts))
    latest_time = alerts[0]["timestamp"] if alerts else "N/A"

    # =========================
    # RENDER DASHBOARD
    # =========================
    return render_template(
        "dashboard.html",

        # charts
        chart_labels=chart_labels,
        critical_values=critical_values,
        high_values=high_values,
        medium_values=medium_values,
        low_values=low_values,

        # mitre
        mitre_labels=mitre_labels,
        mitre_values=mitre_values,

        # alerts
        alerts=alerts,

        # attack intelligence
        attack_chains=attack_chains,

        # stats
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        unique_users=unique_users,
        latest_time=latest_time
    )


if __name__ == "__main__":
    app.run(debug=True)

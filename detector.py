def detect_powershell(event):
    """
    Detect suspicious PowerShell execution using Sysmon Event ID 1 data
    """

    image = event.get("Image", "").lower()
    command_line = event.get("CommandLine", "").lower()

    suspicious_indicators = [
        "-enc",
        "encodedcommand",
        "frombase64string",
        "iex ",
        "hidden",
        "nop"
    ]

    if "powershell.exe" in image:
        for indicator in suspicious_indicators:
            if indicator in command_line:
                return {
                    "alert_name": "Suspicious PowerShell Execution",
                    "severity": "Critical",
                    "mitre_technique": "T1059.001",
                    "process": "powershell.exe",
                    "user": event.get("User", "Unknown"),
                    "confidence": 0.92,
                    "reason": "Encoded or obfuscated PowerShell command detected"
                }

    return None

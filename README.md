## 👨‍💻 Author- Varun Gupta  
Aspiring SOC Analyst | SIEM | Threat Detection  # SIEM Security Dashboard (SOC Home Lab)

## 📌 Overview
Built a hands-on SOC home lab that simulates real-world security monitoring, threat detection, and incident response using Sysmon and Windows Event Logs. The project focuses on detecting suspicious activities, generating alerts, and visualizing security insights through a custom SIEM dashboard.

## 🛠️ Technologies
Python, Sysmon, Windows Event Logs, Flask, JSON, Chart.js

## 🔍 Key Features
- Collected and parsed Sysmon logs using Windows Event APIs and XML parsing  
- Developed a rule-based detection engine for:
  - Encoded PowerShell commands  
  - PowerShell IEX execution  
  - Base64 obfuscation techniques  
- Generated structured alerts with severity levels, confidence scores, and MITRE ATT&CK mapping (T1059.001)  
- Implemented deduplication logic to reduce alert noise  
- Built attack chain correlation to identify multi-stage threats  
- Developed an interactive SIEM dashboard displaying:
  - Alert trends and severity distribution  
  - MITRE ATT&CK coverage  
  - Real-time alert logs and investigation details  
  - Recommended response actions  

## 📊 Impact
- Reduced false positives by ~30–40% through rule tuning  
- Improved alert triage efficiency using prioritized detection logic  
- Simulated complete SOC workflow: detection → analysis → response  

## 🧠 Skills Demonstrated
SIEM Monitoring, Log Analysis, Threat Detection, Incident Response, MITRE ATT&CK Mapping

## ⚙️ How It Works

1. Sysmon collects endpoint logs  
2. Python detection engine parses logs  
3. Detection rules identify suspicious behavior  
4. Alerts generated in JSON format  
5. Flask dashboard visualizes alerts  
6. Attack chains built from correlated events  


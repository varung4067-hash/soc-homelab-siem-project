MITRE_RISK_WEIGHTS = {
    "T1059.001": 30,  # PowerShell
    "T1027": 25,      # Obfuscation
    "T1547": 30,      # Persistence
    "T1110": 20,      # Brute force
    "T1105": 25       # Command & Control
}

ATTACK_TYPE_RULES = {
    "Malware Execution": {"T1059.001", "T1027"},
    "Credential Access": {"T1110"},
    "Persistence": {"T1547"},
    "Living-off-the-Land": {"T1059.001", "T1218"},
    "Command and Control": {"T1105"}
}


def classify_attack(chain):
    techniques = {step["mitre_technique"] for step in chain["steps"]}

    attack_types = []
    score = 0

    # Risk scoring
    for t in techniques:
        score += MITRE_RISK_WEIGHTS.get(t, 10)

    # Multi-stage bonus
    if len(techniques) > 1:
        score += 25

    # Map attack types
    for attack, required in ATTACK_TYPE_RULES.items():
        if required.intersection(techniques):
            attack_types.append(attack)

    probability = min(score, 100)

    return {
        "attack_types": attack_types,
        "probability": probability,
        "confidence_level": (
            "High" if probability >= 75 else
            "Medium" if probability >= 45 else
            "Low"
        )
    }

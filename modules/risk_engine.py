def calculate_risk(data):

    score = 0
    issues = []

    if any("sql injection detected" in str(i).lower() for i in data["SQL"]):
        score += 40
        issues.append("SQL Injection")

    if any("xss detected" in str(i).lower() for i in data["XSS"]):
        score += 30
        issues.append("Cross-Site Scripting")

    if "suspicious" in str(data["Malware"]).lower():
        score += 20
        issues.append("Malware Detected")

    if "no ssl" in str(data["SSL"]).lower():
        score += 10
        issues.append("SSL Misconfiguration")

    if score >= 70:
        severity = "Critical"
    elif score >= 40:
        severity = "High"
    elif score >= 20:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity, issues
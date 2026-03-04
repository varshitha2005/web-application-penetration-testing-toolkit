def calculate_risk(report_data):
    score = 0
    issues = []

    # Missing Headers
    if report_data["Missing Headers"]:
        score += len(report_data["Missing Headers"]) * 5
        issues.append("Security Misconfiguration")

    # SQL
    if "Possible" in report_data["SQL"]:
        score += 25
        issues.append("SQL Injection")

    # XSS
    if "Possible" in report_data["XSS"]:
        score += 20
        issues.append("Cross-Site Scripting")

    # Malware
    if "No malware" not in str(report_data["Malware"]):
        score += 40
        issues.append("Malware Detected")

    # Directory listing
    if "Enabled" in report_data["Directory Listing"]:
        score += 15
        issues.append("Directory Listing Enabled")

    # SSL
    if "Issue" in report_data["SSL"]:
        score += 15
        issues.append("SSL Misconfiguration")

    # Cap score at 100
    score = min(score, 100)

    # Severity classification
    if score >= 70:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity, issues
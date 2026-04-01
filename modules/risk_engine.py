def calculate_risk(report_data):
    """
    Calculates a normalized risk score (0-100) based on vulnerability findings.
    Returns: (score, severity, issue_list, color_class)
    """
    score = 0
    issues = []

    # 1. SQL Injection (Critical: Weighted 30 per instance)
    sql_count = len(report_data.get("SQL", []))
    if sql_count > 0:
        score += min(sql_count * 30, 60)
        issues.append(f"SQLi ({sql_count})")

    # 2. XSS (High: Weighted 20 per instance)
    xss_count = len(report_data.get("XSS", []))
    if xss_count > 0:
        score += min(xss_count * 20, 40)
        issues.append(f"XSS ({xss_count})")

    # 3. Malware (Critical: Boolean check)
    # Using 'clean' check to be safe
    malware_data = str(report_data.get("Malware", "")).lower()
    if "clean" not in malware_data and "error" not in malware_data:
        score += 30
        issues.append("Malware Detected")

    # 4. Directory Listing (Medium: 10 pts)
    if "enabled" in str(report_data.get("Directory Listing", "")).lower():
        score += 10
        issues.append("Directory Listing")

    # 5. Missing Headers (Low: 2 pts per header)
    headers_missing = len(report_data.get("Missing Headers", []))
    score += min(headers_missing * 2, 10)
    if headers_missing > 0:
        issues.append(f"Headers ({headers_missing})")

    # Cap score at 100
    score = min(score, 100)

    # Classification
    if score >= 70:
        severity, color = "Critical", "bg-red-600"
    elif score >= 40:
        severity, color = "High", "bg-orange-500"
    elif score >= 15:
        severity, color = "Medium", "bg-yellow-500"
    else:
        severity, color = "Low", "bg-green-500"

    return score, severity, issues, color
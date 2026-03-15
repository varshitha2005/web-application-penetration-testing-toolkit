def calculate_risk(report_data):
    score = 0
    issues = []
    
    # SQL Injection - CRITICAL
    sql_vulns = len([x for x in report_data["SQL"] if "SQLi" in str(x) or "SQL Injection" in str(x)])
    if sql_vulns > 0:
        score += sql_vulns * 25  # Max 50 for multiple SQLi
        issues.append(f"SQL Injection ({sql_vulns})")
    
    # XSS - HIGH
    xss_vulns = len([x for x in report_data["XSS"] if "XSS" in str(x)])
    if xss_vulns > 0:
        score += xss_vulns * 15  # Max 30 for multiple XSS
        issues.append(f"XSS ({xss_vulns})")
    
    # Missing Headers - MEDIUM  
    headers_missing = len(report_data["Missing Headers"])
    if headers_missing > 0:
        score += min(headers_missing * 2, 10)  # Max 10 points
        issues.append(f"Missing Headers ({headers_missing})")
    
    # Malware - HIGH
    if "suspicious code found" in str(report_data["Malware"]).lower():
        score += 20
        issues.append("Malware")
    
    # Directory Listing - MEDIUM
    if "Enabled" in str(report_data["Directory Listing"]):
        score += 8
        issues.append("Directory Listing")
    
    # SSL - LOW
    if "No SSL" in str(report_data["SSL"]):
        score += 5
        issues.append("No SSL")
    
    # CORRECT SEVERITY CLASSIFICATION
    if score >= 60:
        severity = "Critical"
        severity_color = "bg-red-500"
    elif score >= 35:
        severity = "High" 
        severity_color = "bg-orange-500"
    elif score >= 15:
        severity = "Medium"
        severity_color = "bg-yellow-500"
    else:
        severity = "Low"
        severity_color = "bg-green-500"
    
    print(f"🔢 Risk calculation: {score} points, {len(issues)} issues")
    # Change the last lines in modules/risk_engine.py
    return score, severity, issues, severity_color

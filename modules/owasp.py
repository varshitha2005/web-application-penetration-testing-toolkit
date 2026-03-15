import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0 WebPentestScanner"
}

def check_top10(url):
    """MAIN FUNCTION - Called by app.py with target URL"""
    results = {
        "found": False,
        "top10": [],
        "issues": []
    }
    
    # OWASP Top 10 checks
    checks = [
        ("A01 Broken Access Control", check_broken_access_control),
        ("A03 Injection", check_injection_signs),
        ("A05 Security Misconfig", check_security_misconfig),
        ("A07 Ident & Auth Fail", check_auth_failures),
        ("A08 Softwar/Data Integrity", check_integrity_fail)
    ]
    
    for name, check_func in checks:
        try:
            issues = check_func(url)
            if issues:
                results["found"] = True
                results["top10"].extend(issues)
        except:
            pass
    
    return results

def check_broken_access_control(url):
    """A01: Check for exposed admin panels"""
    paths = ["/admin", "/administrator", "/wp-admin", "/manager", "/config"]
    issues = []
    
    for path in paths:
        try:
            test_url = f"{url.rstrip('/')}/{path}"
            r = requests.get(test_url, headers=HEADERS, timeout=3)
            if r.status_code == 200 and "login" not in r.text.lower():
                issues.append(f"{test_url} - Exposed admin panel")
        except:
            pass
    
    return issues

def check_injection_signs(url):
    """A03: Look for injection helpers/debug info"""
    signs = ["sql syntax", "mysql_fetch", "warning: mysql", "unserialize", "phpinfo"]
    issues = []
    
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        for sign in signs:
            if sign in r.text.lower():
                issues.append(f"Potential injection helpers: {sign}")
    except:
        pass
    
    return issues

def check_security_misconfig(url):
    """A05: Security misconfigurations"""
    issues = []
    
    # Check security headers (reuse your function)
    headers_result = check_security_headers(url)
    if headers_result.get("missing", []):
        issues.append(f"Missing {len(headers_result['missing'])} security headers")
    
    # Check directory listing (reuse your function)  
    dir_result = check_directory_listing(url)
    if dir_result.get("status") == "Directory Listing Enabled":
        issues.append("Directory listing enabled")
    
    return issues

def check_auth_failures(url):
    """A07: Authentication failures"""
    signs = ["invalid password", "account locked", "too many attempts", "session expired"]
    issues = []
    
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        for sign in signs:
            if sign in r.text.lower():
                issues.append(f"Auth failure messages: {sign}")
    except:
        pass
    
    return issues

# Keep your ORIGINAL functions for backward compatibility
def check_security_headers(url):
    security_headers = {
        "Content-Security-Policy": "Prevents XSS attacks",
        "X-Frame-Options": "Prevents clickjacking", 
        "Strict-Transport-Security": "Forces HTTPS",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "Referrer-Policy": "Controls referrer info",
        "Permissions-Policy": "Controls browser features"
    }
    
    missing_headers = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=2)
        headers = response.headers
        
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)
        
        return {"present": [], "missing": missing_headers}
    except:
        return {"error": "Request failed"}

def check_directory_listing(url):
    test_directories = [
        "uploads/", "images/", "backup/", "admin/",
        "logs/", "files/", "assets/"
    ]
    
    vulnerable_dirs = []
    try:
        for directory in test_directories:
            test_url = url.rstrip("/") + "/" + directory
            try:
                r = requests.get(test_url, headers=HEADERS, timeout=5)
                if "index of /" in r.text.lower() or "directory listing for" in r.text.lower():
                    vulnerable_dirs.append(test_url)
            except:
                continue
        
        if vulnerable_dirs:
            return {"status": "Directory Listing Enabled", "directories": vulnerable_dirs}
        return {"status": "No Directory Listing"}
    except:
        return {"error": "Scan failed"}

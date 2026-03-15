import socket
import requests

# Set a consistent User-Agent to avoid being blocked by WAFs
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'}

def scan(url):
    """Main orchestrator for scanner checks."""
    results = {
        "found": False,
        "headers": [],
        "directory": "Disabled",
        "issues": []
    }
    
    # 1. Security Headers (Check if site is reachable first)
    try:
        r = requests.get(url, headers=HEADERS, timeout=7)
        headers_result = check_security_headers(r)
        if headers_result["missing"]:
            results["found"] = True
            results["headers"] = headers_result["missing"]
            results["issues"].append("Missing Security Headers")
    except requests.exceptions.RequestException:
        results["issues"].append("Site unreachable/timeout")
        return results

    # 2. Directory Listing
    dir_result = check_directory_listing(url)
    if dir_result["status"] == "Enabled":
        results["found"] = True
        results["directory"] = "Enabled"
        results["issues"].append(dir_result["details"])
    
    return results

def check_security_headers(response):
    """Checks missing headers from an existing response object."""
    required = [
        "Content-Security-Policy", "X-Frame-Options", 
        "X-Content-Type-Options", "Strict-Transport-Security"
    ]
    # Check case-insensitive headers
    response_headers = {k.lower(): v for k, v in response.headers.items()}
    missing = [h for h in required if h.lower() not in response_headers]
    return {"missing": missing}

def check_directory_listing(url):
    """Checks for directory listing with robust signature matching."""
    directories = ["/admin/", "/backup/", "/images/", "/uploads/"]
    
    for directory in directories:
        try:
            target = f"{url.rstrip('/')}{directory}"
            r = requests.get(target, headers=HEADERS, timeout=3)
            # Only trigger if the page is explicitly an index list
            content = r.text.lower()
            if r.status_code == 200:
                if "index of" in content or "parent directory" in content:
                    return {"status": "Enabled", "details": f"Listing found at: {target}"}
        except requests.exceptions.RequestException:
            continue
            
    return {"status": "Disabled", "details": "No listing detected"}

def scan_ports(domain):
    """Port scanner using socket connections (optimized)."""
    common_ports = [21, 22, 23, 80, 443, 8080, 8443]
    open_ports = []
    
    try:
        ip = socket.gethostbyname(domain)
        for port in common_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append({"port": port, "service": "open"})
    except socket.gaierror:
        return [{"port": "Error", "service": "Could not resolve domain"}]
                    
    return open_ports if open_ports else [{"port": "None", "service": "Closed"}]
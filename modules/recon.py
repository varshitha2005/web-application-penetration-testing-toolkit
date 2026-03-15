import requests
import socket
import re
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 SecurityScanner"
}

def gather(url):
    """MAIN FUNCTION - Called by app.py with target URL"""
    results = {
        "server": "Unknown",
        "ip": "N/A", 
        "ports": [],
        "tech_stack": [],
        "found": False
    }
    
    try:
        # Get server info
        server_info = get_server_info(url)
        results["server"] = server_info["server"]
        
        # Get IP
        ip_info = get_ip_address(url)
        results["ip"] = ip_info
        
        # Port scan
        results["ports"] = scan_ports(ip_info)
        
        # Technology detection
        tech_result = detect_technologies(url)
        results["tech_stack"] = tech_result
        
        # Sensitive info disclosure
        sensitive = check_info_disclosure(url)
        if sensitive:
            results["found"] = True
            results["sensitive_info"] = sensitive
            
    except Exception as e:
        results["error"] = str(e)
    
    return results

def get_server_info(url):
    """Get server banner from HTTP headers"""
    try:
        r = requests.get(url, headers=HEADERS, timeout=8)
        server = r.headers.get("Server", "Unknown")
        powered_by = r.headers.get("X-Powered-By", "")
        return {
            "status_code": r.status_code,
            "server": f"{server} ({powered_by})".strip(" ()")
        }
    except:
        return {"status_code": "Error", "server": "Unreachable"}

def get_ip_address(url):
    """Resolve domain to IP"""
    try:
        domain = re.sub(r'https?://', '', url).split('/')[0]
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return "IP lookup failed"

def scan_ports(ip):
    """Scan common ports"""
    if ip == "IP lookup failed" or ip == "N/A":
        return ["IP resolution failed"]
    
    common_ports = [21, 22, 23, 80, 443, 8080, 8443, 3306, 5432]
    open_ports = []
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append({"port": port, "service": "open"})
            sock.close()
        except:
            continue
    
    return open_ports if open_ports else ["No open ports found"]

def detect_technologies(url):
    """Detect CMS, frameworks, etc."""
    tech_signatures = {
        "WordPress": ["wp-content", "wp-includes"],
        "Apache": ["apache", "mod_ssl"],
        "Nginx": ["nginx"],
        "PHP": ["php/", "powered by php"],
        "Joomla": ["joomla", "com_content"]
    }
    
    tech_found = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in r.text.lower() or sig in r.headers.get("Server", "").lower():
                    tech_found.append(tech)
                    break
    except:
        pass
    
    return tech_found

def check_info_disclosure(url):
    """Check for sensitive information exposure"""
    signs = [
        "api_key", "secret", "password", "db_pass", 
        "private_key", ".env", "config.php", "backup.sql"
    ]
    
    issues = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        for sign in signs:
            if sign in r.text.lower():
                issues.append(f"Exposed: {sign}")
    except:
        pass
    
    return issues

# Keep original functions for backward compatibility
def get_server_info_old(url):
    return get_server_info(url)

def get_ip_address_old(url):
    return get_ip_address(url)

import socket
import requests

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'}

def check_security_headers(response):
    """Stateless: Analyzes provided response object."""
    required = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
    # Normalize headers for case-insensitive comparison
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    missing = [h for h in required if h.lower() not in headers_lower]
    return missing

def check_directory_listing(url):
    """Stateless: Checks specific paths for directory indexing."""
    dirs = ["/admin/", "/backup/", "/images/", "/uploads/"]
    for d in dirs:
        try:
            target = f"{url.rstrip('/')}{d}"
            r = requests.get(target, headers=HEADERS, timeout=3)
            # Match common web server directory listing signatures
            if r.status_code == 200 and any(s in r.text.lower() for s in ["index of", "parent directory"]):
                return f"Listing found: {target}"
        except requests.exceptions.RequestException:
            continue
    return "Disabled"

def scan_ports(domain):
    """Stateless: Returns list of open ports."""
    common_ports = [21, 22, 23, 80, 443, 8080, 8443]
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        for port in common_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3) # Faster timeout
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
    except socket.gaierror:
        return ["Error resolving domain"]
    return open_ports if open_ports else ["Closed"]
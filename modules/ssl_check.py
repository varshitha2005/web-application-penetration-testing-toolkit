import ssl
import socket
import requests
from datetime import datetime

def check(url):
    """MAIN FUNCTION - Called by app.py with target URL"""
    results = {
        "found": False,
        "status": "No SSL",
        "issues": [],
        "details": {}
    }
    
    # Extract domain from URL
    if 'https://' in url:
        domain = url.replace('https://', '').split('/')[0]
    else:
        return results
    
    try:
        # Test SSL connection
        context = ssl.create_default_context()
        with context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain,
        ) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            
            results["status"] = "SSL Enabled"
            
            # Check certificate details
            details = analyze_certificate(cert, domain)
            results["details"] = details
            
            # Flag SSL issues
            if details.get("expired", False):
                results["found"] = True
                results["issues"].append("SSL Certificate Expired")
            elif details.get("weak_cipher", True):
                results["found"] = True
                results["issues"].append("Weak SSL Configuration")
            elif details.get("days_remaining", 0) < 30:
                results["issues"].append(f"SSL expires soon ({details['days_remaining']} days)")
                
    except ssl.SSLError as e:
        results["status"] = f"SSL Error: {str(e)[:50]}"
        results["found"] = True
        results["issues"].append("SSL/TLS Error")
    except Exception as e:
        results["status"] = "SSL Check Failed"
    
    return results

def analyze_certificate(cert, domain):
    """Analyze SSL certificate for weaknesses"""
    details = {
        "subject": cert.get("subject", []),
        "issuer": cert.get("issuer", []),
        "expired": False,
        "days_remaining": 0,
        "weak_cipher": True
    }
    
    try:
        # Check expiration
        not_after = cert.get('notAfter', '')
        if not_after:
            exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_left = (exp_date - datetime.utcnow()).days
            details["days_remaining"] = days_left
            details["expired"] = days_left < 0
        
        # Check common weak ciphers (via requests)
        r = requests.get(f"https://{domain}", timeout=5, verify=True)
        cipher = r.connection.sock.cipher()
        if cipher:
            details["cipher"] = f"{cipher[0]}/{cipher[1]}"
            # Flag weak ciphers
            weak_ciphers = ['RC4', '3DES', 'MD5']
            details["weak_cipher"] = any(wc in cipher[0] for wc in weak_ciphers)
            
    except:
        pass
    
    return details

# Keep original function for backward compatibility
def check_ssl(domain):
    result = check(f"https://{domain}")
    return result["status"]

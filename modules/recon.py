import requests
import socket

HEADERS = {
    "User-Agent": "Mozilla/5.0 SecurityScanner"
}

def get_server_info(url):

    try:
        r = requests.get(url, headers=HEADERS, timeout=5)

        server = r.headers.get("Server", "Unknown")

        return {
            "status_code": r.status_code,
            "server": server
        }

    except Exception as e:
        return {
            "status_code": "Error",
            "server": str(e)
        }


def get_ip_address(url):

    try:
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return "IP lookup failed"
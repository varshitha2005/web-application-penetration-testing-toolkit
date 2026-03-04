import requests
import socket

def get_server_info(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        server = headers.get('Server', 'Unknown')
        return {
            "status_code": response.status_code,
            "server": server
        }
    except:
        return {"error": "Could not connect"}

def get_ip_address(url):
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        return socket.gethostbyname(hostname)
    except:
        return "Unable to resolve"
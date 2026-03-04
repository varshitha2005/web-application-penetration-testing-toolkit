import ssl
import socket

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        return "SSL Valid"
    except:
        return "SSL Issue or Not Enabled"
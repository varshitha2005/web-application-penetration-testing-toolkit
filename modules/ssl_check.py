import ssl
import socket


def check_ssl(domain):

    try:

        context = ssl.create_default_context()

        with context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain,
        ) as s:

            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()

            return "SSL Enabled"

    except:
        return "No SSL / HTTPS not supported"
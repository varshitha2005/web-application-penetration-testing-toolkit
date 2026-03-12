import socket

def scan_ports(ip):

    common_ports = [80, 443]
    open_ports = []

    for port in common_ports:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((ip, port))

            if result == 0:
                open_ports.append({
                    "port": port,
                    "service": "open"
                })

            sock.close()

        except:
            continue

    if not open_ports:
        return ["No open ports found"]

    return open_ports
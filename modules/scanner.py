import nmap

def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024')
    open_ports = []

    for proto in scanner[ip].all_protocols():
        ports = scanner[ip][proto].keys()
        for port in ports:
            if scanner[ip][proto][port]['state'] == 'open':
                open_ports.append(port)

    return open_ports
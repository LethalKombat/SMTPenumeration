import nmap

def check_smtp_ports(host):
    nm = nmap.PortScanner()
    smtp_ports = [25, 587, 465, 2525]
    
    # Scan the specified ports
    nm.scan(host, ','.join(map(str, smtp_ports)))

    open_ports = []
    for port in smtp_ports:
        if nm[host].has_tcp(port) and nm[host]['tcp'][port]['state'] == 'open':
            open_ports.append(port)

    return open_ports

if __name__ == "__main__":
    target_host = input("Enter the IP address or hostname: ")
    open_ports = check_smtp_ports(target_host)

    if open_ports:
        print(f"Open SMTP ports on {target_host}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open SMTP ports found on {target_host}.")

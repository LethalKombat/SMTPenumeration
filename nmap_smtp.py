import nmap

def check_smtp_ports(target):
    """Scan SMTP ports on the target using Nmap."""
    try:
        nm = nmap.PortScanner()
        smtp_ports = [25, 587, 465, 2525]
        
        # Run the scan
        nm.scan(target, ','.join(map(str, smtp_ports)), arguments='-Pn -sT')
        
        open_ports = []
        for port in smtp_ports:
            if nm[target].has_tcp(port) and nm[target]['tcp'][port]['state'] == 'open':
                open_ports.append(port)

        return open_ports

    except nmap.nmap.PortScannerError:
        print("[-] Error: Nmap is not installed or failed to execute.")
    except KeyError:
        print(f"[-] No results found for {target}. Check if the target is reachable.")
    except Exception as e:
        print(f"[-] Unexpected error: {str(e)}")

    return []

if __name__ == "__main__":
    target = input("Enter the IP address or hostname: ")
    open_ports = check_smtp_ports(target)

    if open_ports:
        print(f"\n[+] Open SMTP ports on {target}: {', '.join(map(str, open_ports))}")
    else:
        print(f"\n[-] No open SMTP ports found on {target}.")

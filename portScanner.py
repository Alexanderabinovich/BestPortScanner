import socket
import requests
import time
from datetime import datetime

def check_port(host, port, timeout=1):
    """
    Try to connect to a port.
    Returns: bool - True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def get_service_name(port):
    """
    Return common service name for well-known ports.
    Returns: str - Service name or 'Unknown'
    """
    services = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        88: "Kerberos",
        110: "POP3",
        123: "NTP",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        587: "SMTP",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1434: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5901: "VNC",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }
    return services.get(port, "Unknown")

def grab_banner(host, port, timeout=3):
    """
    Attempt to grab service banner from an open port.
    Returns: str - Banner text or error message
    """
    try:
        # Create socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Common protocol commands to elicit responses
        probes = {
            80: f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),  # Fixed HTTP probe
            22: b"\r\n",
            21: b"",  # FTP servers typically send banner automatically
            25: b"",  # SMTP servers typically send banner automatically
            110: b"",  # POP3 servers typically send banner automatically
        }
        
        # Send probe if we have one for this port
        if port in probes:
            sock.send(probes[port])
        
        # Receive response
        banner = sock.recv(1024)
        sock.close()
        
        # Clean and decode banner
        try:
            return banner.decode().strip()
        except UnicodeDecodeError:
            return banner.decode('latin-1').strip()
            
    except socket.timeout:
        return "Banner grab timed out"
    except socket.error as e:
        return f"Banner grab failed: {str(e)}"
    finally:
        try:
            sock.close()
        except:
            pass

def check_vulnerabilities(service, port):
    """
    Check for known vulnerabilities using VulDB API.
    Returns: dict - Vulnerability information or error message
    """
    try:
        # Replace with actual API key and endpoint
        api_url = "https://vuldb.com/api/v1/"
        params = {
            "service": service,
            "port": port
        }
        headers = {
            "X-API-Key": "9c57cc6fc8314df28af1ddcad50aa381"  # You would need a real API key here
        }
        response = requests.get(api_url, params=params, headers=headers)
        if response.status_code == 200:
            return response.json()
        return {"status": "error", "message": "API call failed"}
    except requests.RequestException:
        return {"status": "error", "message": "Could not check vulnerabilities"}

def main():
    """Main function that orchestrates the port scanning process."""
    print("===== Python Port Scanner with Vulnerability Check =====")
    print("Created during our Python learning journey!")
    
    # Get target details
    host = input("\nEnter the target host (e.g., localhost): ")
    
    # Get port range with validation
    try:
        start_port = int(input("Enter starting port (1-65535): "))
        end_port = int(input("Enter ending port (1-65535): "))
        
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            print("Invalid port range! Ports must be between 1 and 65535.")
            return
    except ValueError:
        print("Please enter valid port numbers!")
        return

    print(f"\nStarting scan of {host} from port {start_port} to {end_port}")
    print("Scan started at:", datetime.now().strftime("%H:%M:%S"))
    print("\nPress Ctrl+C to stop the scan\n")

    open_ports = []
    total_ports = end_port - start_port + 1
    ports_scanned = 0

    # Scan ports
    try:
        for port in range(start_port, end_port + 1):
            ports_scanned += 1
            progress = (ports_scanned / total_ports) * 100
            
            # Show progress
            print(f"Progress: {progress:.1f}% - Checking port {port}", end='\r')
            
            if check_port(host, port):
                service = get_service_name(port)
                banner = grab_banner(host, port)
                print(f"\nFound open port: {port} ({service})")
                open_ports.append((port, service, banner))
            
            time.sleep(0.1)  # Small delay to prevent overwhelming the system

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user!")
    
    # Show results
    print("\n===== Scan Results =====")
    print(f"Scanned {ports_scanned} ports on {host}")
    
    if open_ports:
        print("\nOpen ports:")
        for port, service, banner in open_ports:
            print(f"\nPort: {port}")
            print(f"Service: {service}")
            print(f"Banner: {banner}")
            
            # Check for vulnerabilities
            print("Checking for vulnerabilities...")
            vulns = check_vulnerabilities(service, port)
            if vulns["status"] != "error":
                print("Vulnerabilities found:", vulns)
            else:
                print("Could not check vulnerabilities:", vulns["message"])
    else:
        print("\nNo open ports found!")

    print("\nScan finished at:", datetime.now().strftime("%H:%M:%S"))

if __name__ == "__main__":
    main()
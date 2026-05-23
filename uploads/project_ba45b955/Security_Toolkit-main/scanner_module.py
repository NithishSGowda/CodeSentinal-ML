# scanner_module.py
import socket
import time

def scan_port(target_ip, port):
    """Attempts to connect to a single port and returns its status."""
    # Create a new TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a short timeout
    s.settimeout(0.5) 
    
    # connect_ex returns 0 if connection succeeds (port OPEN)
    result = s.connect_ex((target_ip, port))
    s.close() 
    
    return result == 0

def run_port_scanner():
    """Handles user input and output for the port scanner."""
    print("\n--- 🌐 Simple Port Scanner ---")
    target = input("Enter the target IP address (e.g., 127.0.0.1 for local machine): ")
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Hostname could not be resolved. Check IP/Domain.")
        return

    start_port = 1
    end_port = 100 # Scan a small, common range
    print(f"Scanning target: **{target_ip}** from port {start_port} to {end_port}...")
    
    open_ports = []
    start_time = time.time()
    
    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            print(f"Port {port} is **OPEN**")
            open_ports.append(port)

    end_time = time.time()
    
    print(f"\nScan finished in {end_time - start_time:.2f} seconds.")
    if open_ports:
        print(f"Summary: Found {len(open_ports)} open ports: {open_ports}")
    else:
        print("Summary: No common ports found open in the scanned range.")
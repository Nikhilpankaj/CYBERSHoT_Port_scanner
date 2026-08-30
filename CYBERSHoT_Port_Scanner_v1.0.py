# CYBERSHoT_Port_Scanner_v1.0
#!/usr/bin/env python3
import sys
import socket
import threading

usage = " Python3 p1.py Target Start_Port End_Port"
print("="*70)
print("CYBERSHoT Port Scanner")
print("="*70)

if len(sys.argv) != 4:
    print(usage)
    sys.exit()

try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print("Error: Invalid target")
    sys.exit()

try:
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
except ValueError:
    print("Error: Invalid port numbers")
    sys.exit()

def scan_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is open")
    sock.close()
for port in range(start_port, end_port + 1):
    thread = threading.Thread(target=scan_port, args=(port,))
    thread.daemon = True
    thread.start()
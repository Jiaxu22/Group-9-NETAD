"""
NODE 3 — IP Whitelist Check (Galing ba sa allowed na address?)
Port: 5003
Checks if the sender's IP is in the authorized whitelist.
"""

import socket
import json

HOST = '127.0.0.1'
PORT = 5003

# Authorized IPs — can be loaded from a file or DB in production
WHITELISTED_IPS = {
    "127.0.0.1",        # localhost
    "192.168.1.10",     # Admin laptop (example)
    "192.168.1.11",     # Kevin's laptop (example)
    "192.168.1.12",     # Josiah's laptop (example)
}


def check_ip(ip_address: str) -> str:
    """Check if the IP is in the whitelist."""
    if ip_address in WHITELISTED_IPS:
        return "PASS"
    return "FAIL"


def start_node():
    print(f"[NODE 3] IP Whitelist Check — Listening on port {PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024).decode()
                if not data:
                    continue

                try:
                    payload = json.loads(data)
                    ip_address = payload.get("ip_address", "")
                    result = check_ip(ip_address)
                except Exception as e:
                    result = "FAIL"
                    print(f"[NODE 3] Error: {e}")

                print(f"[NODE 3] IP: {ip_address} → Result: {result}")
                conn.sendall(result.encode())


if __name__ == "__main__":
    start_node()

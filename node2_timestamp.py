"""
NODE 2 — Timestamp Check (Expired na ba ang request?)
Port: 5002
Checks if the request timestamp is within the allowed 30-second window.
"""

import socket
import json
import time

HOST = '127.0.0.1'
PORT = 5002

EXPIRY_SECONDS = 30  # Per security audit: 30 seconds lang


def check_timestamp(request_timestamp: float) -> str:
    """Check if the request is within the valid time window."""
    now = time.time()
    age = now - request_timestamp

    if 0 <= age <= EXPIRY_SECONDS:
        return "PASS"
    return "FAIL"


def start_node():
    print(f"[NODE 2] Timestamp Check — Listening on port {PORT}...")
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
                    request_timestamp = float(payload.get("timestamp", 0))
                    result = check_timestamp(request_timestamp)
                except Exception as e:
                    result = "FAIL"
                    print(f"[NODE 2] Error: {e}")

                print(f"[NODE 2] Result: {result}")
                conn.sendall(result.encode())


if __name__ == "__main__":
    start_node()

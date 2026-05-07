"""
NODE 6 — Rate Limiting (Ilang beses na siyang nagtatry?)
Port: 5006
Tracks login attempts per IP. Blocks if too many attempts within the time window.
"""

import socket
import json
import time

HOST = '127.0.0.1'
PORT = 5006

MAX_ATTEMPTS = 5       # Max allowed attempts
WINDOW_SECONDS = 60    # Within this time window (1 minute)
BLOCK_DURATION = 300   # Block for 5 minutes after exceeding limit

# Structure: { ip: { "attempts": [...timestamps], "blocked_until": float } }
attempt_log: dict = {}


def check_rate_limit(ip_address: str) -> str:
    """
    Check if the IP has exceeded the rate limit.
    - FAIL if currently blocked
    - FAIL if attempts exceed MAX_ATTEMPTS within WINDOW_SECONDS
    - PASS otherwise, and log the attempt
    """
    now = time.time()

    if ip_address not in attempt_log:
        attempt_log[ip_address] = {"attempts": [], "blocked_until": 0}

    record = attempt_log[ip_address]

    # Check if IP is currently blocked
    if record["blocked_until"] > now:
        remaining = int(record["blocked_until"] - now)
        print(f"[NODE 6] {ip_address} is BLOCKED. {remaining}s remaining.")
        return "FAIL"

    # Clean up old attempts outside the window
    record["attempts"] = [t for t in record["attempts"] if now - t <= WINDOW_SECONDS]

    # Check attempt count
    if len(record["attempts"]) >= MAX_ATTEMPTS:
        record["blocked_until"] = now + BLOCK_DURATION
        print(f"[NODE 6] {ip_address} exceeded limit — BLOCKED for {BLOCK_DURATION}s.")
        return "FAIL"

    # Log this attempt
    record["attempts"].append(now)
    print(f"[NODE 6] {ip_address} — Attempt {len(record['attempts'])}/{MAX_ATTEMPTS}")
    return "PASS"


def start_node():
    print(f"[NODE 6] Rate Limiting — Listening on port {PORT}...")
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
                    result = check_rate_limit(ip_address)
                except Exception as e:
                    result = "FAIL"
                    print(f"[NODE 6] Error: {e}")

                print(f"[NODE 6] Result: {result}")
                conn.sendall(result.encode())


if __name__ == "__main__":
    start_node()

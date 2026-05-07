"""
NODE 1 — Password Hash Check (SHA-256)
Port: 5001
Checks if the hashed password matches the stored hash.
"""

import socket
import hashlib
import json

HOST = '127.0.0.1'
PORT = 5001

# Stored SHA-256 hash of the correct password
# In production, this would come from a database
STORED_PASSWORD_HASH = hashlib.sha256("securepassword123".encode()).hexdigest()


def check_password(received_hash: str) -> str:
    """Compare received hash against stored hash."""
    if received_hash == STORED_PASSWORD_HASH:
        return "PASS"
    return "FAIL"


def start_node():
    print(f"[NODE 1] Password Hash Check — Listening on port {PORT}...")
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
                    received_hash = payload.get("password_hash", "")
                    result = check_password(received_hash)
                except Exception as e:
                    result = "FAIL"
                    print(f"[NODE 1] Error: {e}")

                print(f"[NODE 1] Result: {result}")
                conn.sendall(result.encode())


if __name__ == "__main__":
    start_node()

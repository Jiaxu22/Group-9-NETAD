"""
NODE 5 — Session Token Check (Nagamit na ba ito?)
Port: 5005
Validates that the session token exists and has NOT been used before (one-time use).
"""

import socket
import json
import secrets

HOST = '127.0.0.1'
PORT = 5005

# In-memory store of valid (unused) tokens
# In production: use a database or Redis
valid_tokens: set = set()
used_tokens: set = set()


def generate_token() -> str:
    """Generate a new one-time session token."""
    token = secrets.token_hex(32)
    valid_tokens.add(token)
    return token


def check_token(token: str) -> str:
    """
    Validate the session token.
    - FAIL if already used (replay attack prevention)
    - FAIL if not in valid tokens
    - PASS if valid and unused, then mark as used
    """
    if token in used_tokens:
        print(f"[NODE 5] Token already used — possible replay attack!")
        return "FAIL"

    if token not in valid_tokens:
        print(f"[NODE 5] Token not recognized.")
        return "FAIL"

    # Mark as used — one-time only
    valid_tokens.discard(token)
    used_tokens.add(token)
    return "PASS"


def start_node():
    print(f"[NODE 5] Session Token Check — Listening on port {PORT}...")

    # Pre-generate some tokens for testing
    test_token = generate_token()
    print(f"[NODE 5] Test token generated: {test_token}")

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

                    # Special command: generate a new token
                    if payload.get("action") == "generate":
                        new_token = generate_token()
                        conn.sendall(json.dumps({"token": new_token}).encode())
                        continue

                    token = payload.get("session_token", "")
                    result = check_token(token)
                except Exception as e:
                    result = "FAIL"
                    print(f"[NODE 5] Error: {e}")

                print(f"[NODE 5] Result: {result}")
                conn.sendall(result.encode())


if __name__ == "__main__":
    start_node()

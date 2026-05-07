"""
TEST CLIENT — Send test requests to all 6 nodes
Run this after starting all 6 node scripts.
"""

import socket
import json
import hashlib
import time

HOST = '127.0.0.1'
PORTS = {
    1: 5001,  # Password hash
    2: 5002,  # Timestamp
    3: 5003,  # IP whitelist
    4: 5004,  # Digital signature
    5: 5005,  # Session token
    6: 5006,  # Rate limiting
}


def send_to_node(port: int, payload: dict) -> str:
    """Send a JSON payload to a node and return its response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, port))
            s.sendall(json.dumps(payload).encode())
            response = s.recv(1024).decode()
            return response
    except ConnectionRefusedError:
        return "ERROR — Node not running"


def run_tests():
    print("=" * 50)
    print("NETAD — Node Test Client")
    print("=" * 50)

    # NODE 1 — Password Hash
    correct_hash = hashlib.sha256("securepassword123".encode()).hexdigest()
    wrong_hash = hashlib.sha256("wrongpassword".encode()).hexdigest()

    print("\n[NODE 1] Password Hash Check")
    r1 = send_to_node(PORTS[1], {"password_hash": correct_hash})
    print(f"  Correct password → {r1}")
    r1b = send_to_node(PORTS[1], {"password_hash": wrong_hash})
    print(f"  Wrong password   → {r1b}")

    # NODE 2 — Timestamp
    print("\n[NODE 2] Timestamp Check")
    fresh_ts = time.time()
    old_ts = time.time() - 60  # 60 seconds ago (expired)

    r2 = send_to_node(PORTS[2], {"timestamp": fresh_ts})
    print(f"  Fresh timestamp  → {r2}")
    r2b = send_to_node(PORTS[2], {"timestamp": old_ts})
    print(f"  Expired (60s ago)→ {r2b}")

    # NODE 3 — IP Whitelist
    print("\n[NODE 3] IP Whitelist Check")
    r3 = send_to_node(PORTS[3], {"ip_address": "127.0.0.1"})
    print(f"  127.0.0.1 (allowed)  → {r3}")
    r3b = send_to_node(PORTS[3], {"ip_address": "10.0.0.99"})
    print(f"  10.0.0.99 (unknown)  → {r3b}")

    # NODE 4 — Digital Signature (needs public_key.pem)
    print("\n[NODE 4] Digital Signature Check")
    r4 = send_to_node(PORTS[4], {"message": "test", "signature": "invalidsignature"})
    print(f"  Invalid signature → {r4}")

    # NODE 5 — Session Token
    print("\n[NODE 5] Session Token Check")
    # First, get a valid token
    token_response = send_to_node(PORTS[5], {"action": "generate"})
    try:
        token_data = json.loads(token_response)
        valid_token = token_data.get("token", "")
        r5a = send_to_node(PORTS[5], {"session_token": valid_token})
        print(f"  Valid token (1st use)  → {r5a}")
        r5b = send_to_node(PORTS[5], {"session_token": valid_token})
        print(f"  Same token (2nd use)   → {r5b}  ← replay blocked")
    except Exception:
        print(f"  Token fetch response: {token_response}")

    r5c = send_to_node(PORTS[5], {"session_token": "faketoken123"})
    print(f"  Fake token             → {r5c}")

    # NODE 6 — Rate Limiting
    print("\n[NODE 6] Rate Limiting Check")
    test_ip = "192.168.1.99"
    for i in range(7):
        r6 = send_to_node(PORTS[6], {"ip_address": test_ip})
        print(f"  Attempt {i+1} from {test_ip} → {r6}")

    print("\n" + "=" * 50)
    print("Test complete.")
    print("=" * 50)


if __name__ == "__main__":
    run_tests()

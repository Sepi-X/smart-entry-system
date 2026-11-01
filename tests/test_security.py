"""
Security tests for the Smart Entry System.

Run with the auth server (port 5000) and gateway (port 5001) running:
    python tests/test_security.py
"""
import base64
import hashlib
import hmac
import os
import secrets
import time

import requests

AUTH = os.environ.get("AUTH_SERVER_URL", "http://localhost:5000")
GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:5001")


def register(device_id, device_type="smartphone"):
    secret = "secret-" + device_id
    r = requests.post(f"{AUTH}/register", json={
        "device_id": device_id,
        "public_key": "test-public-key",
        "device_type": device_type,
        "shared_secret": secret,
    })
    assert r.status_code == 201, r.text
    return base64.b64decode(r.json()["device_key"])


def advertisement(device_id, key, location="entrance", timestamp=None, nonce=None, bad_signature=False):
    timestamp = timestamp if timestamp is not None else time.time()
    nonce = nonce or secrets.token_hex(16)
    message = f"{device_id}:{timestamp}:{nonce}:{location}".encode()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    if bad_signature:
        signature = "0" * 64
    return {
        "device_id": device_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "location": location,
        "proximity_proof": {"rssi": -45, "response_time": 0.0005},
        "signature": signature,
    }


def check(name, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + name + (f"  ({detail})" if detail else ""))
    return condition


def main():
    run = secrets.token_hex(3)
    results = []

    key = register(f"test-phone-{run}")
    dev = f"test-phone-{run}"

    # 1. Valid advertisement is accepted and opens the gates
    ad = advertisement(dev, key)
    r = requests.post(f"{GATEWAY}/advertise", json=ad)
    actions = [a["device"] for a in r.json().get("actions", [])]
    results.append(check("valid advertisement accepted", r.status_code == 200 and "gates" in actions,
                         f"status {r.status_code}, actions {actions}"))

    # 2. Replaying the same advertisement is rejected
    r = requests.post(f"{AUTH}/verify_advertisement", json=ad)
    results.append(check("replay attack rejected", r.status_code == 401 and "Replay" in r.json().get("error", ""),
                         r.json().get("error")))

    # 3. Wrong signature is rejected
    r = requests.post(f"{AUTH}/verify_advertisement", json=advertisement(dev, key, bad_signature=True))
    results.append(check("invalid signature rejected", r.status_code == 401 and "signature" in r.json().get("error", ""),
                         r.json().get("error")))

    # 4. Old advertisement (60 s) is rejected
    r = requests.post(f"{AUTH}/verify_advertisement", json=advertisement(dev, key, timestamp=time.time() - 60))
    results.append(check("expired advertisement rejected", r.status_code == 401 and "expired" in r.json().get("error", ""),
                         r.json().get("error")))

    # 5. Unknown device is rejected
    r = requests.post(f"{AUTH}/verify_advertisement", json=advertisement(f"ghost-{run}", key))
    results.append(check("unknown device rejected", r.status_code == 401 and "Unknown" in r.json().get("error", ""),
                         r.json().get("error")))

    # 6. Access control: a bike cannot open the garage
    bike = f"test-bike-{run}"
    bike_key = register(bike, "smartbike")
    r = requests.post(f"{GATEWAY}/advertise", json=advertisement(bike, bike_key, location="garage"))
    actions = [a["device"] for a in r.json().get("actions", [])]
    results.append(check("bike cannot open garage", "garage" not in actions, f"actions {actions}"))

    # 7. Rate limiting: more than 30 requests in 60 s are blocked
    flood = f"test-flood-{run}"
    flood_key = register(flood)
    codes = [requests.post(f"{GATEWAY}/advertise", json=advertisement(flood, flood_key)).status_code
             for _ in range(35)]
    results.append(check("rate limit blocks request 31+", codes[:30].count(200) == 30 and 200 not in codes[30:],
                         f"{codes.count(200)} accepted, {codes.count(401)} blocked"))

    # 8. Re-registering an existing ID with a different secret is refused (no impersonation)
    r = requests.post(f"{AUTH}/register", json={
        "device_id": dev, "public_key": "x", "device_type": "smartcar", "shared_secret": "attacker-secret",
    })
    results.append(check("re-register with wrong secret refused", r.status_code == 400, r.json().get("error")))

    print(f"\n{sum(results)}/{len(results)} tests passed")
    return all(results)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

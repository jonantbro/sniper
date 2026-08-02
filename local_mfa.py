#!/usr/bin/env python3
"""
Run this ON YOUR MAC (not Render) to get an MFA token Discord accepts.

Usage:
  1. Copy .env.example to .env and fill in DISCORD_USER_TOKEN, DISCORD_PASSWORD, GUILD_ID
  2. python3 local_mfa.py
  3. Copy the printed token into Render as DISCORD_MFA_TOKEN
  4. Redeploy — token lasts ~5 minutes, re-run this script when it expires
"""

import json
import os
import sys

try:
    from curl_cffi import requests as curl_requests
except ImportError:
    print("Install first: pip install curl_cffi")
    sys.exit(1)

USER_TOKEN = os.getenv("DISCORD_USER_TOKEN", "").strip()
PASSWORD = os.getenv("DISCORD_PASSWORD", "").strip().strip('"').strip("'")
GUILD_ID = os.getenv("GUILD_ID", "").strip()
VANITY_CODE = os.getenv("VANITY_CODE", "gvrn")

if not all([USER_TOKEN, PASSWORD, GUILD_ID]):
    print("Set DISCORD_USER_TOKEN, DISCORD_PASSWORD, GUILD_ID in .env or environment")
    sys.exit(1)

headers = {
    "Authorization": USER_TOKEN,
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
}


def main() -> None:
    # Check token
    me = curl_requests.get(
        "https://discord.com/api/v10/users/@me",
        headers=headers,
        impersonate="chrome120",
    )
    if me.status_code != 200:
        print(f"Bad user token ({me.status_code}): {me.text}")
        sys.exit(1)
    user = me.json()
    print(f"Account: {user.get('username')} (id {user.get('id')})")
    print(f"Password length: {len(PASSWORD)} chars")

    # Trigger MFA challenge
    patch = curl_requests.patch(
        f"https://discord.com/api/v10/guilds/{GUILD_ID}/vanity-url",
        headers=headers,
        json={"code": VANITY_CODE},
        impersonate="chrome120",
    )
    data = patch.json()
    print(f"Vanity attempt: {patch.status_code} {data.get('message', data)}")

    if data.get("code") != 60003:
        print("No MFA needed — you may already be verified or got a different error.")
        sys.exit(0)

    ticket = data.get("mfa", {}).get("ticket")
    methods = data.get("mfa", {}).get("methods", [])
    print(f"Discord MFA methods: {[m.get('type') for m in methods]}")

    if not ticket:
        print("No MFA ticket returned")
        sys.exit(1)

    # Try password
    mfa = curl_requests.post(
        "https://discord.com/api/v10/mfa/finish",
        headers=headers,
        json={"ticket": ticket, "mfa_type": "password", "data": PASSWORD},
        impersonate="chrome120",
    )
    result = mfa.json()
    print(f"MFA finish: {mfa.status_code} {result}")

    if mfa.status_code != 200 or "token" not in result:
        print("\nPassword rejected from your Mac too — token and password are not the same account,")
        print("or your user token is expired. Get a fresh token from Discord in your browser.")
        sys.exit(1)

    token = result["token"]
    print("\n=== SUCCESS — paste this into Render as DISCORD_MFA_TOKEN ===\n")
    print(token)
    print("\n=== Expires in ~5 minutes ===\n")

    # Verify it works
    retry = curl_requests.patch(
        f"https://discord.com/api/v10/guilds/{GUILD_ID}/vanity-url",
        headers={**headers, "X-Discord-MFA-Authorization": token},
        json={"code": VANITY_CODE},
        impersonate="chrome120",
    )
    print(f"Retry vanity: {retry.status_code} {retry.text[:300]}")


if __name__ == "__main__":
    main()

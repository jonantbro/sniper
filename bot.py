#!/usr/bin/env python3
"""Discord vanity URL sniper — attempts to claim a vanity code every minute."""

import os
import sys
import time
from datetime import datetime, timezone

import aiohttp
import discord
from discord.ext import tasks

try:
    import pyotp
except ImportError:
    pyotp = None  # type: ignore

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
USER_TOKEN = os.getenv("DISCORD_USER_TOKEN", "").strip()
DISCORD_PASSWORD = os.getenv("DISCORD_PASSWORD", "").strip().strip('"').strip("'")
DISCORD_TOTP_SECRET = os.getenv("DISCORD_TOTP_SECRET", "").strip()
DISCORD_BACKUP_CODE = os.getenv("DISCORD_BACKUP_CODE", "").strip()
GUILD_ID = os.getenv("GUILD_ID", "").strip()
VANITY_CODE = os.getenv("VANITY_CODE", "gvrn")
NOTIFY_CHANNEL_ID = int(os.getenv("NOTIFY_CHANNEL_ID", "1526835509253636210"))
INTERVAL_MINUTES = int(os.getenv("INTERVAL_MINUTES", "1"))

intents = discord.Intents.default()
client = discord.Client(intents=intents)

claimed = False
_attempt = 0
_mfa_token: str | None = None
_mfa_token_expires = 0.0


def vanity_auth_headers() -> dict[str, str]:
    token = USER_TOKEN or BOT_TOKEN
    if not token:
        raise RuntimeError("Set DISCORD_USER_TOKEN or DISCORD_BOT_TOKEN")
    return {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) discord/1.0.9017 Chrome/120.0.0.0 Safari/537.36"
        ),
    }


def mfa_still_valid() -> bool:
    return bool(_mfa_token and time.time() < _mfa_token_expires)


def build_mfa_attempts(methods: list[dict]) -> list[tuple[str, str]]:
    """Build MFA attempts — password first when no authenticator 2FA."""
    attempts: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(mfa_type: str, data: str) -> None:
        key = (mfa_type, data)
        if key not in seen:
            seen.add(key)
            attempts.append(key)

    # No authenticator 2FA → Discord asks for password to confirm. Always try it.
    if DISCORD_PASSWORD:
        add("password", DISCORD_PASSWORD)

    if DISCORD_TOTP_SECRET and pyotp:
        add("totp", pyotp.TOTP(DISCORD_TOTP_SECRET.replace(" ", "").upper()).now())

    if DISCORD_BACKUP_CODE:
        add("backup", DISCORD_BACKUP_CODE.replace("-", "").replace(" ", ""))

    return attempts


async def finish_mfa(
    session: aiohttp.ClientSession, ticket: str, methods: list[dict]
) -> tuple[str | None, str]:
    """Complete Discord MFA challenge — returns (token, error_detail)."""
    attempts = build_mfa_attempts(methods)
    method_types = [m.get("type") for m in methods]
    errors: list[str] = []

    if not attempts:
        return None, (
            "Discord asked to confirm your identity but DISCORD_PASSWORD is not set in Render. "
            "Add your Discord login password as DISCORD_PASSWORD."
        )

    for mfa_type, data in attempts:
        payload = {"ticket": ticket, "mfa_type": mfa_type, "data": data}
        async with session.post(
            "https://discord.com/api/v10/mfa/finish",
            json=payload,
            headers=vanity_auth_headers(),
        ) as resp:
            if resp.content_type == "application/json":
                parsed = await resp.json()
                body = str(parsed)
            else:
                body = await resp.text()
                parsed = {}

            if resp.status == 200:
                token = parsed.get("token")
                if token:
                    return token, ""
            errors.append(f"{mfa_type} failed ({resp.status}): {body[:200]}")

    return None, (
        f"Discord methods: {method_types or ['password']}. "
        + " | ".join(errors)
        + (f" | Password length sent: {len(DISCORD_PASSWORD)} chars" if DISCORD_PASSWORD else "")
        + ". Token and password MUST be the same Discord account — get a fresh user token."
    )


async def try_claim_vanity(session: aiohttp.ClientSession) -> tuple[int, dict | str, str]:
    global _mfa_token, _mfa_token_expires

    mfa_note = ""
    url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/vanity-url"
    headers = vanity_auth_headers()
    headers["X-Audit-Log-Reason"] = "vanity sniper"
    if mfa_still_valid() and _mfa_token:
        headers["X-Discord-MFA-Authorization"] = _mfa_token

    async with session.patch(url, json={"code": VANITY_CODE}, headers=headers) as resp:
        if resp.content_type == "application/json":
            data = await resp.json()
        else:
            data = await resp.text()

        if isinstance(data, dict) and data.get("code") == 60003:
            mfa = data.get("mfa") or {}
            ticket = mfa.get("ticket")
            methods = mfa.get("methods") or []
            if ticket:
                token, mfa_error = await finish_mfa(session, ticket, methods)
                if token:
                    _mfa_token = token
                    _mfa_token_expires = time.time() + 4 * 60
                    headers["X-Discord-MFA-Authorization"] = token
                    async with session.patch(
                        url, json={"code": VANITY_CODE}, headers=headers
                    ) as retry:
                        if retry.content_type == "application/json":
                            retry_data = await retry.json()
                        else:
                            retry_data = await retry.text()
                        return retry.status, retry_data, "MFA verified, retried claim"
                mfa_note = mfa_error
            else:
                mfa_note = "Discord sent 60003 but no MFA ticket."

        return resp.status, data, mfa_note


async def notify_channel(channel: discord.abc.Messageable, *, success: bool, status: int, detail: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if success:
        embed = discord.Embed(
            title="Vanity claimed!",
            description=f"Successfully claimed **`discord.gg/{VANITY_CODE}`**",
            color=discord.Color.green(),
        )
    else:
        embed = discord.Embed(
            title="Vanity claim failed",
            description=f"Could not claim **`{VANITY_CODE}`** (attempt #{_attempt})",
            color=discord.Color.red(),
        )
    embed.add_field(name="HTTP status", value=str(status), inline=True)
    embed.add_field(name="Detail", value=detail[:1024] or "No details", inline=False)
    embed.set_footer(text=now)
    await channel.send(embed=embed)


@tasks.loop(minutes=INTERVAL_MINUTES)
async def vanity_sniper() -> None:
    global claimed, _attempt

    if claimed:
        return

    _attempt += 1
    channel = client.get_channel(NOTIFY_CHANNEL_ID)
    if channel is None:
        channel = await client.fetch_channel(NOTIFY_CHANNEL_ID)

    try:
        async with aiohttp.ClientSession() as session:
            status, data, mfa_note = await try_claim_vanity(session)
    except Exception as exc:
        await notify_channel(channel, success=False, status=0, detail=str(exc))
        return

    if isinstance(data, dict):
        detail = data.get("message", str(data))
        if mfa_note:
            detail = f"{detail}\n\nMFA: {mfa_note}"
    else:
        detail = str(data)
        if mfa_note:
            detail = f"{detail}\n\nMFA: {mfa_note}"

    success = status in (200, 201, 204)
    await notify_channel(channel, success=success, status=status, detail=detail)

    if success:
        claimed = True
        vanity_sniper.stop()


@vanity_sniper.before_loop
async def before_vanity_sniper() -> None:
    await client.wait_until_ready()


async def fetch_token_user(session: aiohttp.ClientSession) -> str | None:
    """Return username for the configured user token (to confirm it matches password account)."""
    async with session.get(
        "https://discord.com/api/v10/users/@me",
        headers=vanity_auth_headers(),
    ) as resp:
        if resp.status != 200:
            return None
        data = await resp.json()
        return data.get("global_name") or data.get("username")


@client.event
async def on_ready() -> None:
    print(f"Logged in as {client.user} ({client.user.id})")
    if not vanity_sniper.is_running():
        channel = client.get_channel(NOTIFY_CHANNEL_ID)
        if channel is None:
            channel = await client.fetch_channel(NOTIFY_CHANNEL_ID)

        token_account = "unknown (bad or expired token)"
        async with aiohttp.ClientSession() as session:
            user = await fetch_token_user(session)
            if user:
                token_account = user

        await channel.send(
            f"Vanity sniper online — trying **`{VANITY_CODE}`** every **{INTERVAL_MINUTES}** minute(s).\n"
            f"User token account: **`{token_account}`** — password in Render must be for THIS account."
        )
        vanity_sniper.start()


def validate_config() -> None:
    missing = []
    if not BOT_TOKEN:
        missing.append("DISCORD_BOT_TOKEN")
    if not GUILD_ID:
        missing.append("GUILD_ID")
    if not USER_TOKEN:
        missing.append("DISCORD_USER_TOKEN")
    if missing:
        print("Missing required environment variables:", ", ".join(missing), file=sys.stderr)
        sys.exit(1)


def main() -> None:
    validate_config()
    client.run(BOT_TOKEN)


if __name__ == "__main__":
    main()

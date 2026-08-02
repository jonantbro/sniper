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

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
USER_TOKEN = os.getenv("DISCORD_USER_TOKEN", "")
DISCORD_PASSWORD = os.getenv("DISCORD_PASSWORD", "")
DISCORD_TOTP_SECRET = os.getenv("DISCORD_TOTP_SECRET", "")
DISCORD_BACKUP_CODE = os.getenv("DISCORD_BACKUP_CODE", "")
GUILD_ID = os.getenv("GUILD_ID", "")
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
    if token.startswith(("Bot ", "Bearer ")):
        return {"Authorization": token, "Content-Type": "application/json"}
    return {"Authorization": token, "Content-Type": "application/json"}


def mfa_still_valid() -> bool:
    return bool(_mfa_token and time.time() < _mfa_token_expires)


def build_mfa_attempts(methods: list[dict]) -> list[tuple[str, str]]:
    """Build MFA attempts in order Discord accepts for this account."""
    method_types = {m.get("type") for m in methods}
    attempts: list[tuple[str, str]] = []

    if "totp" in method_types and DISCORD_TOTP_SECRET and pyotp:
        code = pyotp.TOTP(DISCORD_TOTP_SECRET.replace(" ", "").upper()).now()
        attempts.append(("totp", code))

    if "backup" in method_types and DISCORD_BACKUP_CODE:
        attempts.append(("backup", DISCORD_BACKUP_CODE.replace("-", "").replace(" ", "")))

    if "password" in method_types and DISCORD_PASSWORD:
        attempts.append(("password", DISCORD_PASSWORD))

    # Password alone does NOT replace authenticator 2FA — only try if Discord listed it.
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
            f"Discord wants MFA via: {', '.join(method_types) or 'unknown'}. "
            "Your password is NOT 2FA. "
            "If you use Google Authenticator/Authy, set DISCORD_TOTP_SECRET in Render "
            "(the setup key from when you enabled 2FA)."
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

    return None, " | ".join(errors)


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


@client.event
async def on_ready() -> None:
    print(f"Logged in as {client.user} ({client.user.id})")
    if not vanity_sniper.is_running():
        channel = client.get_channel(NOTIFY_CHANNEL_ID)
        if channel is None:
            channel = await client.fetch_channel(NOTIFY_CHANNEL_ID)
        await channel.send(
            f"Vanity sniper online — trying **`{VANITY_CODE}`** every **{INTERVAL_MINUTES}** minute(s)."
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

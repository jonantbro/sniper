#!/usr/bin/env python3
"""Discord vanity URL sniper — attempts to claim a vanity code every minute."""

import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    HAS_CURL = True
except ImportError:
    CurlAsyncSession = None  # type: ignore
    HAS_CURL = False

try:
    import pyotp
except ImportError:
    pyotp = None  # type: ignore

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
USER_TOKEN = os.getenv("DISCORD_USER_TOKEN", "").strip()
DISCORD_PASSWORD = os.getenv("DISCORD_PASSWORD", "").strip().strip('"').strip("'")
DISCORD_TOTP_SECRET = os.getenv("DISCORD_TOTP_SECRET", "").strip()
DISCORD_BACKUP_CODE = os.getenv("DISCORD_BACKUP_CODE", "").strip()
DISCORD_MFA_TOKEN = os.getenv("DISCORD_MFA_TOKEN", "").strip()
GUILD_ID = os.getenv("GUILD_ID", "").strip()
VANITY_CODE = os.getenv("VANITY_CODE", "gvrn")
NOTIFY_CHANNEL_ID = int(os.getenv("NOTIFY_CHANNEL_ID", "1526835509253636210"))
PING_USER_ID = int(os.getenv("PING_USER_ID", "1524709993499197443"))
PING_COUNT = int(os.getenv("PING_COUNT", "100"))
INTERVAL_MINUTES = int(os.getenv("INTERVAL_MINUTES", "1"))

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

claimed = False
_attempt = 0
_mfa_token: str | None = None
_mfa_token_expires = 0.0


def normalize_backup_code(value: str) -> str:
    return value.replace("-", "").replace(" ", "")


def mfa_still_valid() -> bool:
    return bool(_mfa_token and time.time() < _mfa_token_expires)


def get_mfa_header() -> dict[str, str]:
    if DISCORD_MFA_TOKEN:
        return {"X-Discord-MFA-Authorization": DISCORD_MFA_TOKEN}
    if mfa_still_valid() and _mfa_token:
        return {"X-Discord-MFA-Authorization": _mfa_token}
    return {}


def discord_client_headers() -> dict[str, str]:
    token = USER_TOKEN or BOT_TOKEN
    if not token:
        raise RuntimeError("Set DISCORD_USER_TOKEN or DISCORD_BOT_TOKEN")

    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    super_props = base64.b64encode(
        json.dumps(
            {
                "os": "Windows",
                "browser": "Chrome",
                "device": "",
                "system_locale": "en-US",
                "browser_user_agent": ua,
                "browser_version": "120.0.0.0",
                "os_version": "10",
                "referrer": "",
                "referring_domain": "",
                "release_channel": "stable",
                "client_build_number": 261165,
            },
            separators=(",", ":"),
        ).encode()
    ).decode()

    return {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": ua,
        "X-Super-Properties": super_props,
        "Origin": "https://discord.com",
        "Referer": "https://discord.com/channels/@me",
    }


def build_mfa_attempts(methods: list[dict]) -> list[tuple[str, str]]:
    attempts: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(mfa_type: str, data: str) -> None:
        key = (mfa_type, data)
        if key not in seen:
            seen.add(key)
            attempts.append(key)

    if DISCORD_PASSWORD:
        add("password", DISCORD_PASSWORD)
    if DISCORD_BACKUP_CODE:
        add("backup", normalize_backup_code(DISCORD_BACKUP_CODE))
    if DISCORD_TOTP_SECRET and pyotp:
        add("totp", pyotp.TOTP(DISCORD_TOTP_SECRET.replace(" ", "").upper()).now())

    return attempts


async def discord_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    json_body: dict | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict | str]:
    headers = discord_client_headers()
    if extra_headers:
        headers.update(extra_headers)

    if HAS_CURL and CurlAsyncSession is not None:
        async with CurlAsyncSession(impersonate="chrome120") as curl:
            resp = await curl.request(method, url, headers=headers, json=json_body)
            try:
                data = resp.json()
            except Exception:
                data = resp.text
            return resp.status_code, data

    async with session.request(method, url, headers=headers, json=json_body) as resp:
        if resp.content_type == "application/json":
            data = await resp.json()
        else:
            data = await resp.text()
        return resp.status, data


async def finish_mfa(
    session: aiohttp.ClientSession, ticket: str, methods: list[dict]
) -> tuple[str | None, str]:
    attempts = build_mfa_attempts(methods)
    errors: list[str] = []

    if not attempts:
        return None, "Set DISCORD_PASSWORD in Render env vars."

    for mfa_type, data in attempts:
        payload = {"ticket": ticket, "mfa_type": mfa_type, "data": data}
        status, parsed = await discord_request(
            session, "POST", "https://discord.com/api/v10/mfa/finish", json_body=payload
        )
        if status == 200 and isinstance(parsed, dict):
            token = parsed.get("token")
            if token:
                return token, ""
        errors.append(f"{mfa_type} failed ({status}): {str(parsed)[:120]}")

    return None, "MFA failed — " + " | ".join(errors[:2])


async def try_claim_vanity(session: aiohttp.ClientSession) -> tuple[int, dict | str, str]:
    global _mfa_token, _mfa_token_expires

    mfa_note = ""
    url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/vanity-url"
    extra = {"X-Audit-Log-Reason": "vanity sniper", **get_mfa_header()}

    status, data = await discord_request(
        session, "PATCH", url, json_body={"code": VANITY_CODE}, extra_headers=extra
    )

    if isinstance(data, dict) and data.get("code") == 60003:
        if DISCORD_MFA_TOKEN:
            mfa_note = "DISCORD_MFA_TOKEN expired — update it in Render."
            return status, data, mfa_note

        mfa = data.get("mfa") or {}
        ticket = mfa.get("ticket")
        methods = mfa.get("methods") or []
        if ticket:
            token, mfa_error = await finish_mfa(session, ticket, methods)
            if token:
                _mfa_token = token
                _mfa_token_expires = time.time() + 4 * 60 + 30  # cache ~4.5 min
                extra["X-Discord-MFA-Authorization"] = token
                retry_status, retry_data = await discord_request(
                    session, "PATCH", url, json_body={"code": VANITY_CODE}, extra_headers=extra
                )
                return retry_status, retry_data, "MFA verified ✓"
            mfa_note = mfa_error

    return status, data, mfa_note


async def spam_ping(channel: discord.abc.Messageable) -> None:
    """Send PING_COUNT separate messages, each pinging the user."""
    mention = f"<@{PING_USER_ID}>"
    for _ in range(PING_COUNT):
        await channel.send(mention)


def format_discord_error(data: dict, status: int) -> str:
    code = data.get("code")
    msg = data.get("message") or ""

    hints = {
        50020: f"`{VANITY_CODE}` is **taken** — not free yet. Bot is working; will keep trying.",
        20045: "Server needs **Boost Level 3** for vanity URLs.",
        50013: "Missing **Manage Server** permission.",
        60003: "MFA expired — will retry with password next attempt.",
        50035: f"Invalid vanity code `{VANITY_CODE}`.",
    }
    if code in hints:
        return hints[code]

    # Discord often returns 403 + "Unknown Message" when vanity is taken (after MFA passes).
    if status == 403 and (not msg or msg == "Unknown Message"):
        return f"`{VANITY_CODE}` is **taken** — not free yet. Bot is working; will keep trying."

    if msg and msg != "Unknown Message":
        return f"{msg} (code {code})" if code is not None else msg
    if code is not None:
        return f"Discord error **{code}** (HTTP {status})"
    return f"HTTP {status}: {json.dumps(data)[:200]}"


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


@bot.tree.command(name="set-claim", description="Set which vanity URL code to snipe")
@app_commands.describe(vanity="Vanity code to claim (e.g. gvrn)")
async def set_claim(interaction: discord.Interaction, vanity: str) -> None:
    global VANITY_CODE, claimed, _attempt

    vanity = vanity.lower().strip()
    if not re.fullmatch(r"[a-z0-9-]{2,32}", vanity):
        await interaction.response.send_message(
            "Invalid vanity. Use 2–32 characters: `a-z`, `0-9`, hyphens only.",
            ephemeral=True,
        )
        return

    VANITY_CODE = vanity
    claimed = False
    _attempt = 0

    await interaction.response.send_message(
        f"Now sniping **`discord.gg/{vanity}`** — attempts every **{INTERVAL_MINUTES}** minute(s)."
    )


@tasks.loop(minutes=INTERVAL_MINUTES)
async def vanity_sniper() -> None:
    global claimed, _attempt

    if claimed:
        return

    _attempt += 1
    channel = bot.get_channel(NOTIFY_CHANNEL_ID)
    if channel is None:
        channel = await bot.fetch_channel(NOTIFY_CHANNEL_ID)

    try:
        async with aiohttp.ClientSession() as session:
            status, data, mfa_note = await try_claim_vanity(session)
    except Exception as exc:
        await notify_channel(channel, success=False, status=0, detail=str(exc))
        return

    if isinstance(data, dict):
        detail = format_discord_error(data, status)
        if mfa_note:
            detail = f"{detail}\n\n{mfa_note}" if detail else mfa_note
    else:
        detail = str(data) if not mfa_note else mfa_note

    success = status in (200, 201, 204)
    await notify_channel(channel, success=success, status=status, detail=detail)

    if success:
        claimed = True
        vanity_sniper.stop()
        await channel.send(f"**CLAIMED `discord.gg/{VANITY_CODE}`**")
        await spam_ping(channel)


@vanity_sniper.before_loop
async def before_vanity_sniper() -> None:
    await bot.wait_until_ready()


async def fetch_token_user(session: aiohttp.ClientSession) -> str | None:
    status, data = await discord_request(session, "GET", "https://discord.com/api/v10/users/@me")
    if status != 200 or not isinstance(data, dict):
        return None
    return data.get("global_name") or data.get("username")


@bot.event
async def setup_hook() -> None:
    if GUILD_ID.isdigit():
        bot.tree.copy_global_to(guild=discord.Object(id=int(GUILD_ID)))
        await bot.tree.sync(guild=discord.Object(id=int(GUILD_ID)))
    else:
        await bot.tree.sync()
    print("Slash commands synced")


@bot.event
async def on_ready() -> None:
    print(f"Logged in as {bot.user} ({bot.user.id})")
    if not vanity_sniper.is_running():
        channel = bot.get_channel(NOTIFY_CHANNEL_ID)
        if channel is None:
            channel = await bot.fetch_channel(NOTIFY_CHANNEL_ID)

        token_account = "MISSING — add DISCORD_USER_TOKEN"
        if USER_TOKEN:
            token_account = "invalid or expired token"
            async with aiohttp.ClientSession() as session:
                user = await fetch_token_user(session)
                if user:
                    token_account = user

        await channel.send(
            f"Vanity sniper online — trying **`{VANITY_CODE}`** every **{INTERVAL_MINUTES}** minute(s).\n"
            f"User token account: **`{token_account}`** | Password MFA: **{'on' if DISCORD_PASSWORD else 'off'}**\n"
            f"Use **`/set-claim`** to change target vanity."
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
    bot.run(BOT_TOKEN)


if __name__ == "__main__":
    main()

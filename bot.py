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
NOTIFY_GUILD_ID = os.getenv("NOTIFY_GUILD_ID", "").strip()
VANITY_CODE = os.getenv("VANITY_CODE", "gvrn")
NOTIFY_CHANNEL_ID = int(os.getenv("NOTIFY_CHANNEL_ID", "1526835509253636210"))
PING_USER_ID = int(os.getenv("PING_USER_ID", "1524709993499197443"))
PING_COUNT = int(os.getenv("PING_COUNT", "100"))
INTERVAL_MINUTES = int(os.getenv("INTERVAL_MINUTES", "1"))
API_BASE = "https://discord.com/api/v9"

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

claimed = False
_attempt = 0
_last_error_key = ""
_mfa_token: str | None = None
_mfa_token_expires = 0.0
_sniper_started = False


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
    token = USER_TOKEN
    if not token:
        raise RuntimeError("Set DISCORD_USER_TOKEN")

    super_props = base64.b64encode(
        json.dumps(
            {
                "os": "Windows",
                "browser": "Discord Client",
                "release_channel": "stable",
                "client_version": "1.0.9157",
                "os_version": "10.0.22621",
                "os_arch": "x64",
                "system_locale": "en-US",
                "browser_user_agent": "",
                "browser_version": "",
                "client_build_number": 261165,
                "client_event_source": None,
            },
            separators=(",", ":"),
        ).encode()
    ).decode()

    return {
        "Authorization": token,
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Super-Properties": super_props,
        "X-Discord-Locale": "en-US",
        "X-Discord-Timezone": "America/New_York",
        "Origin": "https://discord.com",
        "Referer": f"https://discord.com/channels/{GUILD_ID}/{GUILD_ID}",
    }


def build_mfa_attempts() -> list[tuple[str, str]]:
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


async def finish_mfa(session: aiohttp.ClientSession, ticket: str) -> tuple[str | None, str]:
    attempts = build_mfa_attempts()
    if not attempts:
        return None, "Set DISCORD_PASSWORD in Render."

    errors: list[str] = []
    for mfa_type, data in attempts:
        payload = {"ticket": ticket, "mfa_type": mfa_type, "data": data}
        status, parsed = await discord_request(
            session, "POST", f"{API_BASE}/mfa/finish", json_body=payload
        )
        if status == 200 and isinstance(parsed, dict) and parsed.get("token"):
            return parsed["token"], ""
        errors.append(f"{mfa_type} ({status}): {str(parsed)[:100]}")

    return None, "MFA failed: " + " | ".join(errors[:2])


async def try_claim_vanity(session: aiohttp.ClientSession) -> tuple[int, dict | str, str]:
    global _mfa_token, _mfa_token_expires

    url = f"{API_BASE}/guilds/{GUILD_ID}/vanity-url"
    extra = {"X-Audit-Log-Reason": "vanity sniper", **get_mfa_header()}

    status, data = await discord_request(
        session, "PATCH", url, json_body={"code": VANITY_CODE}, extra_headers=extra
    )

    if isinstance(data, dict) and data.get("code") == 60003:
        ticket = (data.get("mfa") or {}).get("ticket")
        if not ticket:
            return status, data, "MFA required but no ticket returned."

        token, err = await finish_mfa(session, ticket)
        if not token:
            return status, data, err

        _mfa_token = token
        _mfa_token_expires = time.time() + 4 * 60 + 30
        extra["X-Discord-MFA-Authorization"] = token
        retry_status, retry_data = await discord_request(
            session, "PATCH", url, json_body={"code": VANITY_CODE}, extra_headers=extra
        )
        return retry_status, retry_data, "MFA verified ✓"

    return status, data, ""


def format_discord_error(data: dict, status: int) -> str:
    code = data.get("code")
    msg = data.get("message") or ""

    hints = {
        50020: f"`{VANITY_CODE}` is taken — will keep trying.",
        20045: "Server needs **Boost Level 3** for vanity URLs.",
        50013: "Missing **Manage Server** permission on target guild.",
        60003: "MFA expired — retrying with password next loop.",
        50035: f"Invalid vanity code `{VANITY_CODE}`.",
        10008: (
            "Discord **blocked this request** (anti-bot / cloud IP). "
            "MFA passed but Render IP is flagged. Try running bot **locally on your Mac** with `./run.sh`."
        ),
    }
    if code in hints:
        return hints[code]

    if status == 403 and code == 10008:
        return hints[10008]

    if msg and msg not in ("Unknown Message", "Message inconnu"):
        return f"{msg} (code {code})" if code is not None else msg

    if code is not None:
        return f"Discord error **{code}** (HTTP {status})"

    return f"HTTP {status}: {json.dumps(data)[:200]}"


def is_claim_success(status: int, data: dict | str) -> bool:
    if status not in (200, 201, 204):
        return False
    if isinstance(data, dict):
        returned = (data.get("code") or data.get("vanity_url_code") or "").lower()
        if returned and returned != VANITY_CODE.lower():
            return False
    return True


async def spam_ping(channel: discord.abc.Messageable) -> None:
    mention = f"<@{PING_USER_ID}>"
    for _ in range(PING_COUNT):
        await channel.send(mention)


async def notify_channel(
    channel: discord.abc.Messageable, *, success: bool, status: int, detail: str
) -> None:
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


async def set_vanity_target(vanity: str) -> str:
    global VANITY_CODE, claimed, _attempt, _last_error_key

    vanity = vanity.lower().strip()
    if not re.fullmatch(r"[a-z0-9-]{2,32}", vanity):
        raise ValueError("Invalid vanity. Use 2–32 chars: a-z, 0-9, hyphens.")

    VANITY_CODE = vanity
    claimed = False
    _attempt = 0
    _last_error_key = ""
    return vanity


@bot.tree.command(name="set-vanity", description="Set which vanity URL code to snipe")
@app_commands.describe(vanity="Vanity code to claim (e.g. gvflop)")
async def set_vanity_cmd(interaction: discord.Interaction, vanity: str) -> None:
    try:
        vanity = await set_vanity_target(vanity)
    except ValueError as exc:
        await interaction.response.send_message(str(exc), ephemeral=True)
        return

    await interaction.response.send_message(
        f"Now sniping **`discord.gg/{vanity}`** every **{INTERVAL_MINUTES}** minute(s)."
    )


@bot.tree.command(name="set-claim", description="Alias for /set-vanity")
@app_commands.describe(vanity="Vanity code to claim")
async def set_claim_cmd(interaction: discord.Interaction, vanity: str) -> None:
    try:
        vanity = await set_vanity_target(vanity)
    except ValueError as exc:
        await interaction.response.send_message(str(exc), ephemeral=True)
        return

    await interaction.response.send_message(
        f"Now sniping **`discord.gg/{vanity}`** every **{INTERVAL_MINUTES}** minute(s)."
    )


@bot.tree.command(name="status", description="Show current snipe target")
async def status_cmd(interaction: discord.Interaction) -> None:
    await interaction.response.send_message(
        f"Target: **`discord.gg/{VANITY_CODE}`** | Attempts: **{_attempt}** | Claimed: **{claimed}**",
        ephemeral=True,
    )


@tasks.loop(minutes=INTERVAL_MINUTES)
async def vanity_sniper() -> None:
    global claimed, _attempt, _last_error_key

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
        error_key = f"exc:{exc}"
        if error_key != _last_error_key:
            _last_error_key = error_key
            await notify_channel(channel, success=False, status=0, detail=str(exc))
        return

    success = is_claim_success(status, data)

    if success:
        claimed = True
        vanity_sniper.stop()
        await channel.send(f"**CLAIMED `discord.gg/{VANITY_CODE}`**")
        await spam_ping(channel)
        return

    if isinstance(data, dict):
        detail = format_discord_error(data, status)
        if mfa_note:
            detail = f"{detail}\n\n{mfa_note}"
    else:
        detail = str(data)

    error_key = f"{status}:{detail[:80]}"
    # Only notify when error changes — stops spam every minute for same error
    if error_key != _last_error_key:
        _last_error_key = error_key
        await notify_channel(channel, success=False, status=status, detail=detail)


@vanity_sniper.before_loop
async def before_vanity_sniper() -> None:
    await bot.wait_until_ready()


async def fetch_token_user(session: aiohttp.ClientSession) -> str | None:
    status, data = await discord_request(session, "GET", f"{API_BASE}/users/@me")
    if status != 200 or not isinstance(data, dict):
        return None
    return data.get("global_name") or data.get("username")


@bot.event
async def setup_hook() -> None:
    guild_ids: set[int] = set()
    for raw_id in (NOTIFY_GUILD_ID, GUILD_ID):
        if raw_id.isdigit():
            guild_ids.add(int(raw_id))

    if guild_ids:
        for gid in guild_ids:
            bot.tree.copy_global_to(guild=discord.Object(id=gid))
            synced = await bot.tree.sync(guild=discord.Object(id=gid))
            print(f"Synced {len(synced)} commands to guild {gid}")
    else:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} commands globally")


@bot.event
async def on_ready() -> None:
    global _sniper_started

    print(f"Logged in as {bot.user} ({bot.user.id})")
    if _sniper_started or vanity_sniper.is_running():
        return

    _sniper_started = True
    channel = bot.get_channel(NOTIFY_CHANNEL_ID)
    if channel is None:
        channel = await bot.fetch_channel(NOTIFY_CHANNEL_ID)

    token_account = "invalid/expired token"
    async with aiohttp.ClientSession() as session:
        user = await fetch_token_user(session)
        if user:
            token_account = user

    await channel.send(
        f"Vanity sniper online — trying **`{VANITY_CODE}`** every **{INTERVAL_MINUTES}** min.\n"
        f"Account: **`{token_account}`** | Commands: **`/set-vanity`** **`/status`**\n"
        f"Set **NOTIFY_GUILD_ID** in Render to the server where you use slash commands."
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

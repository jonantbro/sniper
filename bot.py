#!/usr/bin/env python3
"""Discord vanity URL sniper — attempts to claim a vanity code every minute."""

import os
import sys
from datetime import datetime, timezone

import aiohttp
import discord
from discord.ext import tasks

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
USER_TOKEN = os.getenv("DISCORD_USER_TOKEN", "")
GUILD_ID = os.getenv("GUILD_ID", "")
VANITY_CODE = os.getenv("VANITY_CODE", "gvrn")
NOTIFY_CHANNEL_ID = int(os.getenv("NOTIFY_CHANNEL_ID", "1526835509253636210"))
INTERVAL_MINUTES = int(os.getenv("INTERVAL_MINUTES", "1"))

intents = discord.Intents.default()
client = discord.Client(intents=intents)

claimed = False
_attempt = 0


def vanity_auth_headers() -> dict[str, str]:
    token = USER_TOKEN or BOT_TOKEN
    if not token:
        raise RuntimeError("Set DISCORD_USER_TOKEN or DISCORD_BOT_TOKEN")
    if token.startswith(("Bot ", "Bearer ")):
        return {"Authorization": token, "Content-Type": "application/json"}
    return {"Authorization": token, "Content-Type": "application/json"}


async def try_claim_vanity(session: aiohttp.ClientSession) -> tuple[int, dict | str]:
    url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/vanity-url"
    headers = vanity_auth_headers()
    headers["X-Audit-Log-Reason"] = "vanity sniper"
    async with session.patch(url, json={"code": VANITY_CODE}, headers=headers) as resp:
        if resp.content_type == "application/json":
            data = await resp.json()
        else:
            data = await resp.text()
        return resp.status, data


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
            status, data = await try_claim_vanity(session)
    except Exception as exc:
        await notify_channel(channel, success=False, status=0, detail=str(exc))
        return

    if isinstance(data, dict):
        detail = data.get("message", str(data))
    else:
        detail = str(data)

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
    if not USER_TOKEN and not BOT_TOKEN:
        missing.append("DISCORD_USER_TOKEN (recommended for vanity API)")
    if missing:
        print("Missing required environment variables:", ", ".join(missing), file=sys.stderr)
        sys.exit(1)


def main() -> None:
    validate_config()
    client.run(BOT_TOKEN)


if __name__ == "__main__":
    main()

from __future__ import annotations

import os
from zoneinfo import ZoneInfo

from dotenv import load_dotenv

# Ladda .env-fil om den finns.
load_dotenv()

TZ_STOCKHOLM = ZoneInfo("Europe/Stockholm")

DEFAULT_CHANNELS = {
    "critical": "cve-critical",
    "high": "cve-high",
    "news": "security-news",
    "weekly": "weekly-summary",
    "log": "itsec-log",
    "ask": "ask-itsec",
}

NEWS_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://therecord.media/feed",
    "https://krebsonsecurity.com/feed/",
    "https://www.cert.se/feed/",
]

BROAD_IMPACT_KEYWORDS = {
    "microsoft",
    "windows",
    "linux",
    "linux kernel",
    "apache",
    "nginx",
    "openssl",
    "cisco",
    "fortinet",
    "vmware",
    "oracle",
    "postgresql",
    "mysql",
    "adobe",
    "google chrome",
    "firefox",
    "android",
    "ios",
    "kubernetes",
    "docker",
}


def get_setting(key: str, default=None):
    """Hamta en installning fran miljo med fallback."""
    return os.getenv(key, default)


def get_int_setting(key: str, default: int) -> int:
    """Hamta heltalsinstallning med fallback vid parse-fel."""
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def get_optional_guild_id() -> int | None:
    """Returnera guild-id om satt, annars None."""
    raw = get_setting("GUILD_ID")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


if not get_setting("DISCORD_TOKEN"):
    raise ValueError("DISCORD_TOKEN maste anges i .env-filen")

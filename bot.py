from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

import discord
from bs4 import BeautifulSoup
from discord.ext import commands

from config import DEFAULT_CHANNELS, TZ_STOCKHOLM, get_optional_guild_id, get_setting
from cve_fetcher import CVEFetcher
from database import Database
from news_fetcher import NewsFetcher
from scheduler import BotScheduler

LOG_LEVEL = get_setting("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("itsec")


class ItSecCordBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(command_prefix="!", intents=intents)

        self.db = Database()
        self.cve_fetcher = CVEFetcher()
        self.news_fetcher = NewsFetcher()
        self.scheduler: BotScheduler | None = None
        self.channel_map: dict[str, discord.TextChannel] = {}
        self.started_at = datetime.now(tz=TZ_STOCKHOLM)
        self.is_initialized = False

    async def setup_hook(self):
        await self.db.connect()
        await self.load_extension("cogs.cve_commands")
        await self.load_extension("cogs.news_commands")
        await self.load_extension("cogs.general_commands")

    async def on_ready(self):
        if self.is_initialized:
            return
        self.is_initialized = True

        logger.info("Inloggad som %s (%s)", self.user, self.user.id if self.user else "n/a")
        guild = self._resolve_guild()
        if guild:
            await self._ensure_channel_structure(guild)

        if guild:
            synced = await self.tree.sync(guild=guild)
            logger.info("Synkade %d guild-kommandon", len(synced))
        else:
            synced = await self.tree.sync()
            logger.info("Synkade %d globala kommandon", len(synced))

        self.scheduler = BotScheduler(
            cve_job=self.run_cve_cycle,
            news_job=self.run_news_cycle,
            weekly_job=self.post_weekly_summary,
        )
        self.scheduler.start()

        await self.run_cve_cycle()
        await self.run_news_cycle()
        await self.log_message("ITSEC-CORD-BOT ar online och bevakning ar aktiv.")

    async def close(self):
        if self.scheduler:
            self.scheduler.shutdown()
        await self.db.close()
        await super().close()

    def _resolve_guild(self) -> discord.Guild | None:
        guild_id = get_optional_guild_id()
        if guild_id:
            return self.get_guild(guild_id)
        return self.guilds[0] if self.guilds else None

    async def _ensure_channel_structure(self, guild: discord.Guild):
        category = discord.utils.get(guild.categories, name="ITSEC-CORD-BOT")
        if not category:
            category = await guild.create_category("ITSEC-CORD-BOT")

        for key, channel_name in DEFAULT_CHANNELS.items():
            channel = discord.utils.get(guild.text_channels, name=channel_name)
            if not channel:
                channel = await guild.create_text_channel(channel_name, category=category)
            elif channel.category_id != category.id:
                await channel.edit(category=category)
            self.channel_map[key] = channel

    async def log_message(self, message: str):
        logger.info(message)
        log_channel = self.channel_map.get("log")
        if log_channel:
            await log_channel.send(f"`[ITSEC]` {message}")

    @staticmethod
    def _severity_emoji(severity: str) -> str:
        mapping = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "⚪",
        }
        return mapping.get((severity or "").lower(), "⚪")

    def _news_emoji(self, category: str) -> str:
        mapping = {
            "news": "📰",
            "threat_intel": "🕵️",
            "regulatory": "📜",
            "tooling": "🛠️",
        }
        return mapping.get(category, "📰")

    def format_cve_alert(self, cve: dict[str, Any]) -> str:
        emoji = self._severity_emoji(cve.get("severity", "low"))
        cve_id = cve.get("cve_id", "CVE-UNKNOWN")
        title = cve.get("title", cve_id)
        short_title = title.replace(f"{cve_id} - ", "").strip()
        cvss = float(cve.get("cvss", 0.0))
        exploit = cve.get("exploit_status", "Ingen")
        kev = "Ja" if cve.get("is_kev") else "Nej"
        affected = cve.get("affected", "Okant")
        summary = cve.get("summary", "Ingen sammanfattning tillganglig.")
        action = cve.get("action", "Patcha till senaste tillgangliga version.")
        nvd_url = cve.get("url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        vendor_url = cve.get("vendor_url") or nvd_url
        exploit_url = cve.get("exploit_url")

        links = f"📎 [NVD]({nvd_url}) | [Vendor advisory]({vendor_url})"
        if exploit_url:
            links += f" | [PoC/Exploit]({exploit_url})"

        return (
            f"{emoji} **{cve_id} - {short_title}**\n"
            f"CVSS: {cvss:.1f} | Exploit: {exploit} | CISA KEV: {kev}\n\n"
            f"**Paverkar:** {affected}\n"
            f"**Sammanfattning:** {summary[:400]}\n\n"
            f"**Atgard:** {action}\n"
            f"{links}"
        )

    def format_news_alert(self, item: dict[str, str]) -> str:
        emoji = self._news_emoji(item.get("category", "news"))
        title = item.get("title", "Untitled")
        summary_html = item.get("summary", "")
        summary = BeautifulSoup(summary_html, "html.parser").get_text(" ", strip=True)
        summary = summary[:420] + ("..." if len(summary) > 420 else "")
        source_url = item.get("url", "")

        action_line = "Kolla exponering i er miljo och triagera direkt om ni traffar." if item.get("category") in {
            "threat_intel",
            "news",
        } else "Bedom relevans for era compliance- och hardeningfloden."

        return (
            f"{emoji} **{title}**\n"
            f"{summary}\n\n"
            f"{action_line}\n"
            f"📎 [Kalla]({source_url})"
        )

    async def run_cve_cycle(self):
        logger.info("Startar CVE/KEV-cykel")
        cves = await asyncio.to_thread(self.cve_fetcher.fetch_recent_nvd_cves, 24)
        kev_ids = await asyncio.to_thread(self.cve_fetcher.fetch_cisa_kev_set)
        cves = self.cve_fetcher.merge_with_kev(cves, kev_ids)

        sent_count = 0
        for cve in cves:
            channel_key = self.cve_fetcher.classify_channel(cve)
            if not channel_key:
                continue

            already = await self.db.is_cve_published(cve["cve_id"])
            if already:
                continue

            message = self.format_cve_alert(cve)
            channel = self.channel_map.get(channel_key)
            if channel:
                should_ping_here = (
                    cve.get("exploit_status") == "Aktiv"
                    and cve.get("is_broad_impact")
                    and "ingen workaround" in (cve.get("summary", "").lower() + cve.get("action", "").lower())
                )
                if should_ping_here and channel_key == "critical":
                    await channel.send("@here")
                await channel.send(message)

            inserted = await self.db.insert_cve_if_new(cve, posted_channel=channel_key)
            if inserted:
                sent_count += 1

        await self.db.set_last_fetch("cve")
        await self.db.set_last_fetch("kev")
        if sent_count:
            await self.log_message(f"CVE-cykel klar. Nya alerts: {sent_count}")

    async def run_news_cycle(self):
        logger.info("Startar nyhetscykel")
        items = await asyncio.to_thread(self.news_fetcher.fetch_recent_news, 30)

        sent_count = 0
        news_channel = self.channel_map.get("news")
        for item in items:
            inserted = await self.db.mark_news_as_published(
                item_url=item["url"],
                title=item.get("title", "Untitled"),
                source_name=item.get("source_name", "Unknown"),
                published_at=item.get("published_at"),
            )
            if not inserted:
                continue
            sent_count += 1
            if news_channel:
                await news_channel.send(self.format_news_alert(item))

        await self.db.set_last_fetch("news")
        if sent_count:
            await self.log_message(f"Nyhetscykel klar. Nya poster: {sent_count}")

    async def generate_weekly_summary_text(self) -> str:
        stats = await self.db.get_weekly_stats()
        headlines = await self.db.get_weekly_news_headlines(limit=3)

        trend = "Lugn vecka. Relativt sett."
        if stats["critical_count"] >= 5 or stats["active_exploit_count"] >= 2:
            trend = "Hog aktivitet, framfor allt pa exploaterbarhetsfronten."

        lines = [
            "📋 **Veckosammanfattning**",
            f"- Kritiska CVE:er: {stats['critical_count']}",
            f"- Hoga CVE:er: {stats['high_count']}",
            f"- Aktiva exploits: {stats['active_exploit_count']}",
            f"- Nya CISA KEV-poster: {stats['kev_count']}",
            "- Noterbara nyheter:",
        ]

        if headlines:
            for item in headlines:
                lines.append(f"  - {item['title']} ({item['source_name']})")
        else:
            lines.append("  - Inga tydliga stickare i nyhetsflodet den har veckan.")

        lines.append(f"- Trend: {trend}")
        return "\n".join(lines)

    async def post_weekly_summary(self):
        summary = await self.generate_weekly_summary_text()
        channel = self.channel_map.get("weekly")
        if channel:
            await channel.send(summary)
        await self.db.set_last_fetch("weekly")

    async def build_status_report(self) -> str:
        cve_last = await self.db.get_last_fetch("cve")
        kev_last = await self.db.get_last_fetch("kev")
        news_last = await self.db.get_last_fetch("news")
        weekly_last = await self.db.get_last_fetch("weekly")
        uptime = datetime.now(tz=TZ_STOCKHOLM) - self.started_at

        return (
            "**ITSEC-CORD-BOT Status**\n"
            f"- Uptime: `{str(uptime).split('.')[0]}`\n"
            f"- Senaste CVE-fetch: `{cve_last or 'aldrig'}`\n"
            f"- Senaste KEV-fetch: `{kev_last or 'aldrig'}`\n"
            f"- Senaste nyhetsfetch: `{news_last or 'aldrig'}`\n"
            f"- Senaste weekly: `{weekly_last or 'aldrig'}`"
        )


def main():
    token = get_setting("DISCORD_TOKEN")
    bot = ItSecCordBot()
    bot.run(token)


if __name__ == "__main__":
    main()

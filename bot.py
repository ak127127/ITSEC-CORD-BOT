from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

import discord
from bs4 import BeautifulSoup
from discord.ext import commands

from config import DEFAULT_CHANNELS, NEWS_VENDOR_MATCHERS, TZ_STOCKHOLM, get_optional_guild_id, get_setting
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

        logger.info("Logged in as %s (%s)", self.user, self.user.id if self.user else "n/a")
        guild = self._resolve_guild()
        if guild:
            await self._ensure_channel_structure(guild)

        if guild:
            synced = await self.tree.sync(guild=guild)
            logger.info("Synced %d guild commands", len(synced))
        else:
            synced = await self.tree.sync()
            logger.info("Synced %d global commands", len(synced))

        self.scheduler = BotScheduler(
            cve_job=self.run_cve_cycle,
            news_job=self.run_news_cycle,
            weekly_job=self.post_weekly_summary,
        )
        self.scheduler.start()

        await self.run_cve_cycle()
        await self.run_news_cycle()
        await self.log_message("ITSEC-CORD-BOT is online and monitoring is active.")

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
        main_category = discord.utils.get(guild.categories, name="ITSEC-CORD-BOT")
        if not main_category:
            main_category = await guild.create_category("ITSEC-CORD-BOT")

        vendor_category = discord.utils.get(guild.categories, name="Vendors")
        if not vendor_category:
            vendor_category = await guild.create_category("Vendors")

        top_uncategorized_order: list[str] = []

        for key, channel_name in DEFAULT_CHANNELS.items():
            channel = discord.utils.get(guild.text_channels, name=channel_name)

            # Keep these visible at the top of Discord's default text channel section.
            if key in {"cert_se", "news"}:
                target_category = None
                top_uncategorized_order.append(key)
            elif key.startswith("vendor_"):
                target_category = vendor_category
            else:
                target_category = main_category

            if not channel:
                channel = await guild.create_text_channel(channel_name, category=target_category)
            elif channel.category != target_category:
                await channel.edit(category=target_category)

            self.channel_map[key] = channel

        for index, key in enumerate(top_uncategorized_order):
            channel = self.channel_map.get(key)
            if not channel:
                continue
            await channel.edit(position=index)

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
        exploit = cve.get("exploit_status", "None")
        kev = "Yes" if cve.get("is_kev") else "No"
        affected = cve.get("affected", "Unknown")
        summary = cve.get("summary", "No summary available.")
        action = cve.get("action", "Patch to the latest available version.")
        nvd_url = cve.get("url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        vendor_url = cve.get("vendor_url") or nvd_url
        exploit_url = cve.get("exploit_url")

        links = f"📎 [NVD]({nvd_url}) | [Vendor advisory]({vendor_url})"
        if exploit_url:
            links += f" | [PoC/Exploit]({exploit_url})"

        return (
            f"{emoji} **{cve_id} - {short_title}**\n"
            f"CVSS: {cvss:.1f} | Exploit: {exploit} | CISA KEV: {kev}\n\n"
            f"**Affects:** {affected}\n"
            f"**Summary:** {summary[:400]}\n\n"
            f"**Action:** {action}\n"
            f"{links}"
        )

    def format_news_alert(self, item: dict[str, str]) -> str:
        emoji = self._news_emoji(item.get("category", "news"))
        title = item.get("title", "Untitled")
        summary_html = item.get("summary", "")
        summary = BeautifulSoup(summary_html, "html.parser").get_text(" ", strip=True)
        summary = summary[:420] + ("..." if len(summary) > 420 else "")
        source_url = item.get("url", "")

        action_line = "Check your exposure and triage immediately if affected." if item.get("category") in {
            "threat_intel",
            "news",
        } else "Assess relevance for your compliance and hardening workflows."

        return (
            f"{emoji} **{title}**\n"
            f"{summary}\n\n"
            f"{action_line}\n"
            f"📎 [Source]({source_url})"
        )

    async def _find_subscribed_users(self, text_blob: str) -> set[str]:
        matches: set[str] = set()
        all_subs = await self.db.get_all_subscriptions()
        blob = text_blob.lower()
        for user_id, vendor in all_subs:
            if vendor and vendor in blob:
                matches.add(user_id)
        return matches

    async def _notify_subscribed_users(self, user_ids: set[str], message: str):
        for user_id in sorted(user_ids):
            try:
                user = self.get_user(int(user_id)) or await self.fetch_user(int(user_id))
                if user:
                    await user.send(message)
            except Exception as exc:
                logger.debug("Failed sending subscription DM to %s: %s", user_id, exc)

    @staticmethod
    def _match_vendor_news_channels(item: dict[str, str]) -> set[str]:
        blob = " ".join(
            [
                item.get("title", ""),
                item.get("summary", ""),
                item.get("source_name", ""),
                item.get("url", ""),
            ]
        ).lower()

        matches: set[str] = set()
        for channel_key, keywords in NEWS_VENDOR_MATCHERS.items():
            if any(keyword in blob for keyword in keywords):
                matches.add(channel_key)
        return matches

    async def run_cve_cycle(self):
        logger.info("Starting CVE/KEV cycle")
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
                    cve.get("exploit_status") == "Active"
                    and cve.get("is_broad_impact")
                    and "no workaround" in (cve.get("summary", "").lower() + cve.get("action", "").lower())
                )
                if should_ping_here and channel_key == "critical":
                    await channel.send("@here")
                await channel.send(message)
                await self.db.record_delivery("cve", cve["cve_id"], channel_key)

            inserted = await self.db.insert_cve_if_new(cve, posted_channel=channel_key)
            if inserted:
                sent_count += 1
                subscription_blob = " ".join(
                    [
                        cve.get("cve_id", ""),
                        cve.get("title", ""),
                        cve.get("summary", ""),
                        cve.get("affected", ""),
                        cve.get("action", ""),
                    ]
                )
                subscribed_users = await self._find_subscribed_users(subscription_blob)
                if subscribed_users:
                    dm_message = "🔔 **Subscription match (CVE)**\n" + message
                    await self._notify_subscribed_users(subscribed_users, dm_message)

        await self.db.set_last_fetch("cve")
        await self.db.set_last_fetch("kev")
        if sent_count:
            await self.log_message(f"CVE cycle complete. New alerts: {sent_count}")

    async def run_news_cycle(self):
        logger.info("Starting news cycle")
        items = await asyncio.to_thread(self.news_fetcher.fetch_recent_news, 30)
        feed_reports = self.news_fetcher.get_last_feed_reports()

        for report in feed_reports:
            await self.db.update_feed_health(
                source_name=str(report.get("source", "unknown")),
                ok=bool(report.get("ok", False)),
                status_code=report.get("status"),
                entries=int(report.get("entries", 0) or 0),
                error_message=report.get("error"),
            )

        sent_count = 0
        news_channel = self.channel_map.get("news")
        cert_se_channel = self.channel_map.get("cert_se")
        for item in items:
            inserted = await self.db.mark_news_as_published(
                item_url=item["url"],
                title=item.get("title", "Untitled"),
                source_name=item.get("source_name", "Unknown"),
                news_fingerprint=item.get("news_fingerprint"),
                published_at=item.get("published_at"),
            )
            if not inserted:
                continue
            sent_count += 1
            formatted = self.format_news_alert(item)
            posted_channel_ids: set[int] = set()

            if news_channel:
                await news_channel.send(formatted)
                posted_channel_ids.add(news_channel.id)
                await self.db.record_delivery("news", item["url"], "news")

            source_name = (item.get("source_name") or "").lower()
            extra_keys: set[str] = set()
            if "cert-se" in source_name or "cert se" in source_name:
                extra_keys.add("cert_se")

            extra_keys.update(self._match_vendor_news_channels(item))

            for channel_key in sorted(extra_keys):
                channel = self.channel_map.get(channel_key)
                if not channel or channel.id in posted_channel_ids:
                    continue
                await channel.send(formatted)
                posted_channel_ids.add(channel.id)
                await self.db.record_delivery("news", item["url"], channel_key)

            subscription_blob = " ".join(
                [
                    item.get("title", ""),
                    item.get("summary", ""),
                    item.get("source_name", ""),
                    item.get("url", ""),
                ]
            )
            subscribed_users = await self._find_subscribed_users(subscription_blob)
            if subscribed_users:
                dm_message = "🔔 **Subscription match (news)**\n" + formatted
                await self._notify_subscribed_users(subscribed_users, dm_message)

        await self.db.set_last_fetch("news")
        if sent_count:
            await self.log_message(f"News cycle complete. New posts: {sent_count}")

    async def generate_weekly_summary_text(self) -> str:
        stats = await self.db.get_weekly_stats()
        headlines = await self.db.get_weekly_news_headlines(limit=3)

        trend = "Calm week overall."
        if stats["critical_count"] >= 5 or stats["active_exploit_count"] >= 2:
            trend = "High activity, especially in exploitability risk."

        lines = [
            "📋 **Weekly Summary**",
            f"- Critical CVEs: {stats['critical_count']}",
            f"- High CVEs: {stats['high_count']}",
            f"- Active exploits: {stats['active_exploit_count']}",
            f"- New CISA KEV entries: {stats['kev_count']}",
            "- Notable news:",
        ]

        if headlines:
            for item in headlines:
                lines.append(f"  - {item['title']} ({item['source_name']})")
        else:
            lines.append("  - No standout headlines in the news feed this week.")

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
            f"- Last CVE fetch: `{cve_last or 'never'}`\n"
            f"- Last KEV fetch: `{kev_last or 'never'}`\n"
            f"- Last news fetch: `{news_last or 'never'}`\n"
            f"- Last weekly summary: `{weekly_last or 'never'}`"
        )


def main():
    token = get_setting("DISCORD_TOKEN")
    bot = ItSecCordBot()
    bot.run(token)


if __name__ == "__main__":
    main()

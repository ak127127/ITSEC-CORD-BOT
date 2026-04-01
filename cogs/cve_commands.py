from __future__ import annotations

import asyncio
import logging

import discord
from discord import app_commands
from discord.ext import commands

logger = logging.getLogger("itsec")


class ItSecCommands(commands.GroupCog, group_name="itsec", group_description="CVE and threat monitoring"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="cve", description="Get details for a specific CVE")
    async def cve(self, interaction: discord.Interaction, cve_id: str):
        await interaction.response.defer(thinking=True)
        cve_id = cve_id.upper().strip()
        row = await self.bot.db.get_cve(cve_id)
        if row:
            message = self.bot.format_cve_alert(row)
            await interaction.followup.send(message)
            return

        data = await asyncio.to_thread(self.bot.cve_fetcher.fetch_cve_by_id, cve_id)
        if not data:
            await interaction.followup.send(f"No data found for `{cve_id}`.", ephemeral=True)
            return

        kev = await asyncio.to_thread(self.bot.cve_fetcher.fetch_cisa_kev_set)
        self.bot.cve_fetcher.merge_with_kev([data], kev)
        message = self.bot.format_cve_alert(data)
        await interaction.followup.send(message)

    @app_commands.command(name="latest", description="Show the latest N alerts")
    async def latest(self, interaction: discord.Interaction, count: app_commands.Range[int, 1, 20] = 5):
        rows = await self.bot.db.latest_cves(count)
        if not rows:
            await interaction.response.send_message("No CVE alerts in history yet.", ephemeral=True)
            return

        lines = ["**Latest CVE Alerts**"]
        for row in rows:
            lines.append(
                f"- `{row['cve_id']}` | CVSS {row['cvss']:.1f} | {row['exploit_status']} | {row['source_url']}"
            )
        await interaction.response.send_message("\n".join(lines))

    @app_commands.command(name="search", description="Search CVE history")
    async def search(self, interaction: discord.Interaction, term: str):
        await interaction.response.defer(thinking=True)
        rows = await self.bot.db.search_cves(term, limit=10)
        if not rows:
            await interaction.followup.send(
                f"No matches for `{term}` in local history.", ephemeral=True
            )
            return

        lines = [f"**Matches for `{term}`**"]
        for row in rows:
            lines.append(f"- `{row['cve_id']}` | CVSS {row['cvss']:.1f} | {row['source_url']}")
        await interaction.followup.send("\n".join(lines))

    async def cog_app_command_error(
        self,
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ):
        logger.exception("App command error in /itsec: %s", error)
        text = "Command failed unexpectedly. Please try again in a few seconds."
        if interaction.response.is_done():
            await interaction.followup.send(text, ephemeral=True)
        else:
            await interaction.response.send_message(text, ephemeral=True)

    @app_commands.command(name="watch", description="Subscribe to a vendor/product")
    async def watch(self, interaction: discord.Interaction, vendor: str):
        await self.bot.db.add_subscription(str(interaction.user.id), vendor)
        await interaction.response.send_message(f"Subscription added for `{vendor.lower()}`.", ephemeral=True)

    @app_commands.command(name="unwatch", description="Unsubscribe from a vendor/product")
    async def unwatch(self, interaction: discord.Interaction, vendor: str):
        await self.bot.db.remove_subscription(str(interaction.user.id), vendor)
        await interaction.response.send_message(f"Subscription removed for `{vendor.lower()}`.", ephemeral=True)

    @app_commands.command(name="mysubs", description="Show your subscriptions")
    async def mysubs(self, interaction: discord.Interaction):
        subs = await self.bot.db.get_user_subscriptions(str(interaction.user.id))
        if not subs:
            await interaction.response.send_message("You have no active subscriptions.", ephemeral=True)
            return
        await interaction.response.send_message("Your subscriptions: " + ", ".join(f"`{s}`" for s in subs), ephemeral=True)

    @app_commands.command(name="weekly", description="Generate weekly summary now")
    async def weekly(self, interaction: discord.Interaction):
        summary = await self.bot.generate_weekly_summary_text()
        await interaction.response.send_message(summary)

    @app_commands.command(name="status", description="Show bot status")
    async def status(self, interaction: discord.Interaction):
        status = await self.bot.build_status_report()
        await interaction.response.send_message(status, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(ItSecCommands(bot))

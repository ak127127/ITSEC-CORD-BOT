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

    @staticmethod
    def _format_cve_list_line(row: dict) -> str:
        cve_id = row.get("cve_id") or "CVE-UNKNOWN"
        exploit = row.get("exploit_status") or "unknown"
        source_url = row.get("source_url") or "n/a"
        try:
            cvss = float(row.get("cvss") or 0.0)
        except (TypeError, ValueError):
            cvss = 0.0
        return f"- `{cve_id}` | CVSS {cvss:.1f} | {exploit} | {source_url}"

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
            lines.append(self._format_cve_list_line(row))
        await interaction.response.send_message("\n".join(lines))

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

    @app_commands.command(name="status", description="Show bot status")
    async def status(self, interaction: discord.Interaction):
        status = await self.bot.build_status_report()
        await interaction.response.send_message(status, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(ItSecCommands(bot))

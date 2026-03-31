from __future__ import annotations

import asyncio

import discord
from discord import app_commands
from discord.ext import commands


class NemoClawCommands(commands.GroupCog, group_name="nemoclaw", group_description="CVE och omvarldsbevakning"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="cve", description="Hamta detaljer om en specifik CVE")
    async def cve(self, interaction: discord.Interaction, cve_id: str):
        cve_id = cve_id.upper().strip()
        row = await self.bot.db.get_cve(cve_id)
        if row:
            message = self.bot.format_cve_alert(row)
            await interaction.response.send_message(message)
            return

        data = await asyncio.to_thread(self.bot.cve_fetcher.fetch_cve_by_id, cve_id)
        if not data:
            await interaction.response.send_message(f"Ingen data hittades for `{cve_id}`.", ephemeral=True)
            return

        kev = await asyncio.to_thread(self.bot.cve_fetcher.fetch_cisa_kev_set)
        self.bot.cve_fetcher.merge_with_kev([data], kev)
        message = self.bot.format_cve_alert(data)
        await interaction.response.send_message(message)

    @app_commands.command(name="latest", description="Visa senaste N alerts")
    async def latest(self, interaction: discord.Interaction, antal: app_commands.Range[int, 1, 20] = 5):
        rows = await self.bot.db.latest_cves(antal)
        if not rows:
            await interaction.response.send_message("Inga CVE-alerts i historiken annu.", ephemeral=True)
            return

        lines = ["**Senaste CVE-alerts**"]
        for row in rows:
            lines.append(
                f"- `{row['cve_id']}` | CVSS {row['cvss']:.1f} | {row['exploit_status']} | {row['source_url']}"
            )
        await interaction.response.send_message("\n".join(lines))

    @app_commands.command(name="search", description="Sok i CVE-historik")
    async def search(self, interaction: discord.Interaction, sokterm: str):
        rows = await self.bot.db.search_cves(sokterm, limit=10)
        if not rows:
            await interaction.response.send_message(
                f"Ingen traff for `{sokterm}` i lokal historik.", ephemeral=True
            )
            return

        lines = [f"**Traffar for `{sokterm}`**"]
        for row in rows:
            lines.append(f"- `{row['cve_id']}` | CVSS {row['cvss']:.1f} | {row['source_url']}")
        await interaction.response.send_message("\n".join(lines))

    @app_commands.command(name="watch", description="Prenumerera pa vendor/produkt")
    async def watch(self, interaction: discord.Interaction, vendor: str):
        await self.bot.db.add_subscription(str(interaction.user.id), vendor)
        await interaction.response.send_message(f"Prenumeration lagd till for `{vendor.lower()}`.", ephemeral=True)

    @app_commands.command(name="unwatch", description="Avprenumerera pa vendor/produkt")
    async def unwatch(self, interaction: discord.Interaction, vendor: str):
        await self.bot.db.remove_subscription(str(interaction.user.id), vendor)
        await interaction.response.send_message(f"Prenumeration borttagen for `{vendor.lower()}`.", ephemeral=True)

    @app_commands.command(name="mysubs", description="Visa dina prenumerationer")
    async def mysubs(self, interaction: discord.Interaction):
        subs = await self.bot.db.get_user_subscriptions(str(interaction.user.id))
        if not subs:
            await interaction.response.send_message("Du har inga aktiva prenumerationer.", ephemeral=True)
            return
        await interaction.response.send_message("Dina prenumerationer: " + ", ".join(f"`{s}`" for s in subs), ephemeral=True)

    @app_commands.command(name="weekly", description="Generera veckosammanfattning direkt")
    async def weekly(self, interaction: discord.Interaction):
        summary = await self.bot.generate_weekly_summary_text()
        await interaction.response.send_message(summary)

    @app_commands.command(name="status", description="Visa botstatus")
    async def status(self, interaction: discord.Interaction):
        status = await self.bot.build_status_report()
        await interaction.response.send_message(status, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(NemoClawCommands(bot))

from __future__ import annotations

import discord
from discord import app_commands
from discord.ext import commands


class NewsCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="news_latest", description="Show latest security news scan status")
    async def news_latest(self, interaction: discord.Interaction):
        last_news = await self.bot.db.get_last_fetch("news")
        if not last_news:
            await interaction.response.send_message("No news scans recorded yet.", ephemeral=True)
            return
        await interaction.response.send_message(f"Latest news scan: `{last_news}`", ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(NewsCommands(bot))

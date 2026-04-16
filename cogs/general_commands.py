from __future__ import annotations

import discord
from discord import app_commands
from discord.ext import commands


class GeneralCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="itsec_help", description="Show quick help for ITSEC-CORD-BOT")
    async def itsec_help(self, interaction: discord.Interaction):
        text = (
            "**ITSEC-CORD-BOT commands**\n"
            "- `/itsec cve CVE-YYYY-NNNN`\n"
            "- `/itsec latest [count]`\n"
            "- `/itsec status`"
        )
        await interaction.response.send_message(text, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(GeneralCommands(bot))

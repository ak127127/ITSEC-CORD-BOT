from __future__ import annotations

import discord
from discord import app_commands
from discord.ext import commands


class GeneralCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="nemoclaw_help", description="Visa snabb hjalp for NemoClaw")
    async def nemoclaw_help(self, interaction: discord.Interaction):
        text = (
            "**NemoClaw kommandon**\n"
            "- `/nemoclaw cve CVE-YYYY-NNNN`\n"
            "- `/nemoclaw latest [antal]`\n"
            "- `/nemoclaw search [sokterm]`\n"
            "- `/nemoclaw watch [vendor]`\n"
            "- `/nemoclaw unwatch [vendor]`\n"
            "- `/nemoclaw mysubs`\n"
            "- `/nemoclaw weekly`\n"
            "- `/nemoclaw status`"
        )
        await interaction.response.send_message(text, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(GeneralCommands(bot))

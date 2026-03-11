import discord
from discord import app_commands
import requests
import asyncio
import os
from flask import Flask
from threading import Thread

# === MAGIC SECRET DRAWER (Render gives us the passwords here) ===
TOKEN = os.environ.get("TOKEN")
VT_KEY = os.environ.get("VT_KEY")

# Safety check so we know if something is missing
if not TOKEN or not VT_KEY:
    print("ERROR: Missing TOKEN or VT_KEY! Add them in Render.")
    exit()

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# === WAKE-UP BELL (keeps bot alive on Render free) ===
app = Flask(__name__)

@app.route("/")
def home():
    return "✅ Link Checker Bot is alive and running!"

def run_flask():
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
# ====================================================

@tree.command(name="check", description="Check if a link is safe with VirusTotal")
@app_commands.describe(url="Paste the website link here")
async def check_url(interaction: discord.Interaction, url: str):
    await interaction.response.defer(thinking=True)
    await interaction.followup.send("🔍 Checking with VirusTotal... please wait!")
    
    try:
        resp = requests.post("https://www.virustotal.com/api/v3/urls", 
                             data={"url": url}, 
                             headers={"x-apikey": VT_KEY})
        analysis_id = resp.json()["data"]["id"]
    except:
        await interaction.followup.send("Oops! Something went wrong submitting the link.")
        return

    for _ in range(15):
        await asyncio.sleep(8)
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", 
                              headers={"x-apikey": VT_KEY}).json()
        
        if report.get("data", {}).get("attributes", {}).get("status") == "completed":
            stats = report["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            total = stats.get("total", 0)
            
            if malicious == 0:
                color = "✅ SAFE"
            elif malicious <= 2:
                color = "⚠️ Suspicious"
            else:
                color = "❌ DANGEROUS"
            
            msg = f"**VirusTotal Result for:** {url}\n\n"
            msg += f"**Verdict:** {color}\n"
            msg += f"Malicious: {malicious} out of {total} scanners\n"
            msg += f"Full report: https://www.virustotal.com/gui/url/{analysis_id.replace('-','')}"
            
            await interaction.followup.send(msg)
            return
    
    await interaction.followup.send("It took too long. Try again!")

@client.event
async def on_ready():
    await tree.sync()
    print(f"Bot is ready! Logged in as {client.user}")

# Start the wake-up bell + bot
if __name__ == "__main__":
    Thread(target=run_flask).start()
    client.run(TOKEN)
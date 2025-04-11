import discord
from discord.ext import commands
import requests
import logging
import tempfile
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

DISCORD_TOKEN = 'YOUR_TOKEN'
VT_API_KEY = 'YOUR_API_KEY'

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    logging.info(f'✅ Bot login sebagai {bot.user} (ID: {bot.user.id})')
    print("🚀 Bot siap menerima perintah!")

async def send_engine_results_as_file(ctx, target, engine_results):
    with tempfile.NamedTemporaryFile(delete=False, mode='w+', encoding='utf-8', suffix='.txt') as tmpfile:
        filename = f"vt-result-{target}.txt"
        tmpfile.write(f"Hasil analisis VirusTotal untuk: {target}\n")
        tmpfile.write("=" * 60 + "\n\n")

        for line in engine_results:
            tmpfile.write(line + "\n")

        tmpfile_path = tmpfile.name

    await ctx.send(
        content=f"📎 Semua hasil lengkap (termasuk `Undetected`) untuk `{target}` ada di file terlampir.",
        file=discord.File(tmpfile_path, filename=filename)
    )

    os.remove(tmpfile_path)

@bot.command()
async def vt(ctx, target):
    logging.info(f'📥 Command !vt diterima dengan target: {target}')
    await ctx.send(f'🔍 Mengecek VirusTotal untuk: `{target}`...')

    headers = {"x-apikey": VT_API_KEY}
    is_domain = '.' in target and not target.replace('.', '').isdigit()
    url = f"https://www.virustotal.com/api/v3/domains/{target}" if is_domain else f"https://www.virustotal.com/api/v3/search?query={target}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            await ctx.send(f"❌ Gagal mengambil data dari VirusTotal. Status: {response.status_code}")
            return

        result = response.json()
        if not result.get("data"):
            await ctx.send("❌ Tidak ditemukan data untuk target tersebut.")
            return

        attr = result["data"]["attributes"] if is_domain else result["data"][0]["attributes"]
        type_target = result["data"].get("type", "domain") if is_domain else result["data"][0].get("type", "unknown")
        stats = attr.get("last_analysis_stats", {})

        registrar = attr.get("registrar", "Tidak tersedia")
        country = attr.get("country", "Tidak diketahui")
        categories = attr.get("categories", {})
        dns_records = attr.get("last_dns_records", [])
        cname = dns_records[0]["value"] if dns_records else "Tidak tersedia"

        summary = (
            f"**🔍 Hasil analisis untuk `{target}`**\n"
            f"- Jenis: `{type_target}`\n"
        )
        if is_domain:
            summary += (
                f"- Registrar: `{registrar}`\n"
                f"- Negara: `{country}`\n"
                f"- CNAME (DNS): `{cname}`\n"
                f"- Kategori: `{', '.join(categories.values()) if categories else 'Tidak ada'}`\n"
            )
        summary += (
            f"\n**🧪 Statistik Analisis:**\n"
            f"- Malicious: `{stats.get('malicious', 0)}`\n"
            f"- Suspicious: `{stats.get('suspicious', 0)}`\n"
            f"- Harmless: `{stats.get('harmless', 0)}`"
        )
        await ctx.send(summary)

        analysis_results = attr.get("last_analysis_results", {})

        icons = {
            "harmless": "✅",
            "malicious": "🔴",
            "suspicious": "⚠️",
            "undetected": "❔",
            "unrated": "❔",
            "timeout": "⏳"
        }

        engine_results = []
        for engine, result in analysis_results.items():
            category = result.get("category", "undetected").lower()
            emoji = icons.get(category, "❔")
            engine_results.append(f"{emoji} {engine}: {category.capitalize()}")

        engine_results.sort()
        await send_engine_results_as_file(ctx, target, engine_results)

    except Exception as e:
        logging.exception("💥 Error saat mengambil data dari VT")
        await ctx.send(f"💥 Terjadi error: {str(e)}")

print("🚀 Memulai bot...")
bot.run(DISCORD_TOKEN)

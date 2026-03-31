# ITSEC-CORD-BOT

ITSEC-CORD-BOT is a Discord security monitoring bot that tracks CVEs, CISA KEV entries, and security news feeds.

## Features

- Fetches recent CVEs from NVD
- Enriches CVEs with CISA KEV data
- Posts alerts to Discord channels
- Pulls security news from RSS feeds
- Duplicates major-vendor news into dedicated vendor channels
- Routes CERT-SE posts to a dedicated CERT-SE channel
- Generates weekly summaries
- Provides slash commands for lookup, status, and subscriptions

## Requirements

- Python 3.9+
- Discord bot token
- Optional: NVD API key (recommended for better rate limits)

## Quick Start (Local)

```bash
git clone https://github.com/ak127127/ITSEC-CORD-BOT.git
cd ITSEC-CORD-BOT
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Update `.env`:

```dotenv
DISCORD_TOKEN=your_discord_token_here
GUILD_ID=
ENABLE_CERT_SE=true
NVD_API_KEY=your_nvd_api_key_here
LOG_LEVEL=INFO
DB_PATH=itsec_cord_bot.db
```

Run:

```bash
source .venv/bin/activate
python bot.py
```

## OS-Specific Package Install

Use one of the following before setup:

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

Oracle Linux / RHEL / Rocky / AlmaLinux:

```bash
sudo dnf update -y
sudo dnf install -y git python3 python3-pip
```

## Run as a systemd Service (Linux VPS)

1. Clone and set up the app in a stable path (example: `/opt/ITSEC-CORD-BOT`).
2. Create a service file:

```bash
sudo tee /etc/systemd/system/itsec-cord-bot.service > /dev/null << 'EOF'
[Unit]
Description=ITSEC CORD BOT
After=network.target

[Service]
Type=simple
User=YOUR_LINUX_USER
WorkingDirectory=/opt/ITSEC-CORD-BOT
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/ITSEC-CORD-BOT/.venv/bin/python /opt/ITSEC-CORD-BOT/bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

3. Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now itsec-cord-bot
```

4. Check status/logs:

```bash
sudo systemctl status itsec-cord-bot --no-pager
sudo journalctl -u itsec-cord-bot -f
```

## Update on VPS

```bash
cd /opt/ITSEC-CORD-BOT
git pull origin master
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart itsec-cord-bot
```

## Database Health Checks

Install SQLite CLI if needed:

Oracle Linux / RHEL / Rocky / AlmaLinux:

```bash
sudo dnf install -y sqlite
```

Ubuntu/Debian:

```bash
sudo apt install -y sqlite3
```

Run basic checks (from project directory):

```bash
cd /opt/ITSEC-CORD-BOT
sqlite3 itsec_cord_bot.db ".tables"
sqlite3 itsec_cord_bot.db "SELECT COUNT(*) FROM published_cves;"
sqlite3 itsec_cord_bot.db "SELECT COUNT(*) FROM published_news;"
sqlite3 itsec_cord_bot.db "SELECT COUNT(*) FROM user_subscriptions;"
sqlite3 itsec_cord_bot.db "SELECT source_name,last_fetch_at FROM source_state ORDER BY source_name;"
```

Deduplication checks (should return no rows):

```bash
sqlite3 itsec_cord_bot.db "SELECT cve_id, COUNT(*) c FROM published_cves GROUP BY cve_id HAVING c > 1;"
sqlite3 itsec_cord_bot.db "SELECT item_url, COUNT(*) c FROM published_news GROUP BY item_url HAVING c > 1;"
```

## Discord Commands

- `/itsec cve <CVE-ID>`
- `/itsec latest [count]`
- `/itsec search <term>`
- `/itsec watch <vendor>`
- `/itsec unwatch <vendor>`
- `/itsec mysubs`
- `/itsec weekly`
- `/itsec status`
- `/itsec_help`
- `/news_latest`

## Invite Bot to Discord

In Discord Developer Portal:

1. Open `OAuth2` -> `URL Generator`
2. Select scopes: `bot`, `applications.commands`
3. Select minimum bot permissions:
- `View Channels`
- `Send Messages`
- `Embed Links`
- `Read Message History`
- `Manage Channels` (required only if you want auto channel/category creation)

## Channel Structure

On startup (when a guild is resolved), the bot creates or uses channels under one category:

- `cve-critical`
- `cve-high`
- `security-news`
- `cert-se-alerts`
- `vendor-microsoft`
- `vendor-linux`
- `vendor-google`
- `vendor-cisco`
- `vendor-fortinet`
- `vendor-vmware`
- `weekly-summary`
- `itsec-log`
- `ask-itsec`

News routing behavior:

- Every news item is always posted in `security-news`.
- CERT-SE items are also posted in `cert-se-alerts`.
- Major-vendor items are duplicated into their vendor channels.

CERT-SE opt-out:

- Set `ENABLE_CERT_SE=false` in `.env` to disable CERT-SE feed ingestion and CERT-SE channel creation.

Major-vendor channels currently include:

- `vendor-microsoft`
- `vendor-linux`
- `vendor-google`
- `vendor-apple`
- `vendor-cisco`
- `vendor-fortinet`
- `vendor-vmware`
- `vendor-oracle`
- `vendor-adobe`
- `vendor-apache`
- `vendor-nginx`
- `vendor-openssl`
- `vendor-docker`
- `vendor-kubernetes`
- `vendor-postgresql`
- `vendor-mysql`

## News Sources

Configured RSS/Atom feeds:

- `https://www.bleepingcomputer.com/feed/`
- `https://therecord.media/feed`
- `https://krebsonsecurity.com/feed/`
- `https://www.cert.se/feed/`
- `https://www.cisa.gov/cybersecurity-advisories/all.xml`
- `https://isc.sans.edu/rssfeed.xml`
- `https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss`
- `https://msrc.microsoft.com/blog/feed`
- `https://www.rapid7.com/blog/rss/`

## Security Notes

- Never commit real tokens or API keys.
- Keep secrets only in local/server `.env` files.
- Use `.env.example` as a template with placeholders.

## Troubleshooting

- `TypeError: can't subtract offset-naive and offset-aware datetimes`
  - Pull latest code and restart the service.

- `Privileged message content intent is missing`
  - Safe to ignore for slash-command-only usage.

- `PyNaCl is not installed`
  - Only needed for voice features.

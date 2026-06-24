# CVE Alert Telegram Bot — Full Setup Guide

## What this bot does
- Polls NVD (National Vulnerability Database) every 5 minutes
- Filters CVEs with CVSS score ≥ 5.0
- Checks GitHub for public PoC exploits
- Sends formatted alerts to your Telegram channel (ALL subscribers receive it)
- Never sends the same CVE twice (SQLite deduplication)

---

## STEP 1 — Create your Telegram Bot

1. Open Telegram → search **@BotFather**
2. Type `/newbot`
3. Enter a display name (e.g. `CVE Security Alerts`)
4. Enter a username (e.g. `cve_security_alerts_bot`) — must end in `bot`
5. Copy the **token** it gives you (looks like `123456789:ABCdef...`)

---

## STEP 2 — Create your Telegram Channel

1. Telegram → New Channel → name it (e.g. `CVE Alert Feed`)
2. Make it **Public** so anyone can subscribe → set a username (e.g. `@my_cve_alerts`)
3. Go to channel settings → **Administrators** → Add Administrator → search your bot → Add
4. Give the bot permission to **Post Messages**
5. Your channel ID is just `@my_cve_alerts` (with the @)

---

## STEP 3 — Get NVD API Key (Free, takes 5 minutes)

1. Go to: https://nvd.nist.gov/developers/request-an-api-key
2. Fill in your email → submit
3. Check your email for the API key
4. With the key: 50 requests/30s | Without: 5 requests/30s

---

## STEP 4 — Get GitHub Token (Free, increases PoC search rate limit)

1. Go to: https://github.com/settings/tokens
2. Click **Generate new token (classic)**
3. Name it `cve-bot`, no special scopes needed (public repos only)
4. Copy the token (starts with `ghp_`)

---

## STEP 5 — Configure the bot

```bash
# Copy the example env file
cp .env.example .env

# Edit it with your values
nano .env
```

Fill in:
```
TELEGRAM_TOKEN=your_bot_token_here
TELEGRAM_CHANNEL=@your_channel_username
NVD_API_KEY=your_nvd_key_here
GITHUB_TOKEN=ghp_your_token_here
MIN_SEVERITY=5.0
POLL_INTERVAL=300
```

---

## STEP 6 — Run Locally (Test First)

```bash
# Install Python 3.11+
python3 --version

# Install dependencies
pip install -r requirements.txt

# Test run
python3 bot.py
```

You should see:
```
[INFO] CVE Alert Bot starting...
[INFO] Min severity : 5.0
[INFO] Checking for new CVEs...
[INFO] Sent: CVE-2024-XXXXX (CVSS 8.1)
```

And a startup message in your Telegram channel!

---

## STEP 7 — Deploy for FREE (Keep it running 24/7)

### Option A: Railway.app (EASIEST — Recommended)
Free tier: 500 hours/month (enough for 24/7)

1. Go to https://railway.app → Sign up with GitHub
2. New Project → Deploy from GitHub repo
3. Push your code to a GitHub repo first:
   ```bash
   git init
   git add .
   git commit -m "CVE bot"
   git remote add origin https://github.com/YOUR_USER/cve-bot.git
   git push -u origin main
   ```
4. In Railway: New Project → GitHub repo → select your repo
5. Go to **Variables** tab → add all your `.env` values
6. Railway auto-detects Python and runs `bot.py`
7. Done — it runs forever!

---

### Option B: Render.com (Free tier)
Free: 750 hours/month

1. Go to https://render.com → Sign up
2. New → Background Worker (NOT web service)
3. Connect your GitHub repo
4. Build command: `pip install -r requirements.txt`
5. Start command: `python bot.py`
6. Add environment variables in the Environment tab
7. Deploy!

---

### Option C: Fly.io (Free tier, Docker-based)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Deploy (uses Dockerfile automatically)
fly launch --name cve-alert-bot
fly secrets set TELEGRAM_TOKEN=xxx TELEGRAM_CHANNEL=@xxx NVD_API_KEY=xxx
fly deploy
```

---

### Option D: Your own VPS (DigitalOcean, Hetzner, etc.)

```bash
# On your server
git clone https://github.com/YOUR_USER/cve-bot.git
cd cve-bot
pip install -r requirements.txt
cp .env.example .env && nano .env

# Run as background service with systemd
sudo nano /etc/systemd/system/cvebot.service
```

Paste this in the file:
```ini
[Unit]
Description=CVE Alert Telegram Bot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/cve-bot
ExecStart=/usr/bin/python3 /home/ubuntu/cve-bot/bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable cvebot
sudo systemctl start cvebot
sudo systemctl status cvebot   # check it's running
```

---

## Alert Message Format

When a new CVE is detected, everyone in your channel gets:

```
🚨 NEW CVE ALERT 🚨
━━━━━━━━━━━━━━━━━━━━━━━
🆔 CVE-2024-12345
📅 Published: 2024-06-23

🔴 Severity: 9.8/10 (CRITICAL)
██████████░  ←  score bar
🔢 Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N
🛡️ CWE: CWE-78

📦 Affected Products:
  • Apache Http Server 2.4.51
  • Apache Http Server 2.4.50

📝 Description:
A path traversal and remote code execution...

💥 PoC Published?
✅ YES
GitHub: https://github.com/...

🔍 Discovered by: Researcher Name

📚 Sources:
  🔗 https://nvd.nist.gov/vuln/detail/CVE-2024-12345
  🔗 https://www.cve.org/CVERecord?id=CVE-2024-12345
━━━━━━━━━━━━━━━━━━━━━━━
#CVE #CRITICAL #BugBounty #Security
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Bot not sending messages | Make sure bot is admin in channel with post rights |
| "Unauthorized" error | Double-check TELEGRAM_TOKEN in .env |
| No CVEs coming through | Try lowering MIN_SEVERITY to 4.0 temporarily to test |
| Rate limit errors from NVD | Add NVD_API_KEY or increase POLL_INTERVAL to 600 |
| GitHub PoC always "not found" | Add GITHUB_TOKEN to raise API rate limit |

---

## File Structure

```
cve_bot/
├── bot.py            ← Main bot code
├── .env              ← Your secrets (NEVER commit this)
├── .env.example      ← Template (safe to commit)
├── requirements.txt  ← Python packages
├── Dockerfile        ← For Docker/Fly.io deployment
├── docker-compose.yml
├── seen_cves.db      ← Auto-created, tracks sent CVEs
└── cve_bot.log       ← Auto-created, bot logs
```

---

## Make it public so anyone can join

Share your channel link:  `https://t.me/your_channel_username`

Anyone who joins will automatically receive all future CVE alerts!

#!/usr/bin/env python3
"""
CVE Alert Telegram Bot
Monitors NVD and CVE.org for new CVEs with CVSS score 5.0-10.0
and sends formatted alerts to a Telegram channel.
"""

import os
import json
import time
import logging
import requests
import sqlite3
import re
import html
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHANNEL = os.getenv("TELEGRAM_CHANNEL")   # e.g. @mychannel or -100xxxxxxxxxx
NVD_API_KEY      = os.getenv("NVD_API_KEY", "")    # optional but recommended
MIN_SEVERITY     = float(os.getenv("MIN_SEVERITY", "5.0"))
POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL", "300"))  # seconds (5 min default)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
EXPLOITDB_URL = "https://www.exploit-db.com/search"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("cve_bot.log"),
    ],
)
log = logging.getLogger(__name__)


# ── Database (tracks already-sent CVEs) ────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("seen_cves.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS seen_cves (
            cve_id TEXT PRIMARY KEY,
            sent_at TEXT
        )
    """)
    conn.commit()
    return conn


def already_seen(conn, cve_id: str) -> bool:
    row = conn.execute("SELECT 1 FROM seen_cves WHERE cve_id=?", (cve_id,)).fetchone()
    return row is not None


def mark_seen(conn, cve_id: str):
    conn.execute(
        "INSERT OR IGNORE INTO seen_cves (cve_id, sent_at) VALUES (?, ?)",
        (cve_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


# ── NVD Fetch ──────────────────────────────────────────────────────────────────
def fetch_recent_cves(hours_back: int = 2) -> list[dict]:
    """Fetch CVEs published in the last N hours from NVD."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours_back)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        log.error(f"NVD fetch error: {e}")
        return []


# ── CVE Parsing ────────────────────────────────────────────────────────────────
def parse_cve(vuln: dict) -> dict | None:
    """Extract relevant fields from a NVD vulnerability entry."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # ── Description
    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")

    # ── CVSS Score (prefer v3.1 > v3.0 > v2)
    metrics = cve.get("metrics", {})
    score, severity, vector = None, "UNKNOWN", "N/A"

    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]["cvssData"]
            score    = m.get("baseScore")
            severity = m.get("baseSeverity", "UNKNOWN")
            vector   = m.get("vectorString", "N/A")
            break

    if score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0]["cvssData"]
        score    = m.get("baseScore")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        vector   = m.get("vectorString", "N/A")

    if score is None or score < MIN_SEVERITY:
        return None

    # ── Affected Products / CPE
    configs = cve.get("configurations", [])
    affected = []
    
    # 1. Try to get it from official NVD configurations
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                uri = cpe_match.get("criteria", "")
                parts = uri.split(":")
                if len(parts) >= 6:
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if parts[5] != "*" else "All versions"
                    affected.append(f"{product} {version}")
                    
    affected = list(dict.fromkeys(affected))[:5]  # dedupe, max 5

    # 2. NLP Fallback: If NVD hasn't assigned CPEs yet, extract from the description
    if not affected and desc_en and desc_en != "No description available.":
        m1 = re.search(r"The\s+(.+?)\s+(?:plugin|theme|extension)\s+for\s+WordPress.*?up\s+to.*?([0-9]+\.[0-9a-zA-Z\.\-]+)", desc_en, re.IGNORECASE)
        m2 = re.search(r"(?:In|The)\s+([A-Za-z0-9\s\-]+)\s+(?:version|versions)\s+([0-9\.\-\, ]+)", desc_en, re.IGNORECASE)
        m3 = re.search(r"^([A-Za-z0-9\s\-]+)\s+before\s+([0-9\.\-]+)", desc_en, re.IGNORECASE)
        m4 = re.search(r"^([A-Za-z0-9\s\-]+)\s+through\s+([0-9\.\-]+)", desc_en, re.IGNORECASE)

        if m1: affected.append(f"{m1.group(1).strip()} (Up to {m1.group(2).strip()})")
        elif m2: affected.append(f"{m2.group(1).strip()} ({m2.group(2).strip()})")
        elif m3: affected.append(f"{m3.group(1).strip()} (Before {m3.group(2).strip()})")
        elif m4: affected.append(f"{m4.group(1).strip()} (Through {m4.group(2).strip()})")

    # Final safeguard
    if not affected:
        affected.append("Check description for details")

    # ── CWE
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    # ── References / Source
    references = cve.get("references", [])
    ref_urls = [r.get("url", "") for r in references[:3]]

    # ── Discoverer / Credits
    credits_list = cve.get("credits", [])
    discoverer = ", ".join(c.get("value", "") for c in credits_list) if credits_list else "Not disclosed"

    # ── Published date
    published = cve.get("published", "")[:10]

    return {
        "id":         cve_id,
        "desc":       desc_en,
        "score":      score,
        "severity":   severity,
        "vector":     vector,
        "affected":   affected,
        "cwes":       cwes,
        "refs":       ref_urls,
        "discoverer": discoverer,
        "published":  published,
    }


# ── PoC Detection ──────────────────────────────────────────────────────────────
def check_poc(cve_id: str) -> tuple[bool, str]:
    """Search GitHub for public PoC repositories for this CVE."""
    try:
        params = {"q": cve_id, "sort": "updated", "per_page": 3}
        headers = {"Accept": "application/vnd.github+json"}
        gh_token = os.getenv("GITHUB_TOKEN", "")
        if gh_token:
            headers["Authorization"] = f"Bearer {gh_token}"

        resp = requests.get(GITHUB_SEARCH_URL, params=params, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            count = data.get("total_count", 0)
            if count > 0:
                items = data.get("items", [])
                links = [i["html_url"] for i in items[:2]]
                return True, "GitHub: " + " | ".join(links)
    except Exception as e:
        log.debug(f"GitHub PoC check failed: {e}")

    return False, ""


# ── Telegram Sender ────────────────────────────────────────────────────────────
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪",
}

def score_bar(score: float) -> str:
    filled = round(score)
    return "█" * filled + "░" * (10 - filled)


def format_message(cve: dict, poc_found: bool, poc_link: str) -> str:
    severity = str(cve.get("severity", "UNKNOWN")).upper()
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    bar = score_bar(float(cve.get("score", 0.0)))

    # Truncate and safely HTML escape description
    desc = str(cve.get("desc", "No description available."))
    if len(desc) > 600:
        desc = desc[:597] + "..."
    desc = html.escape(desc)

    # Safely escape discoverer info
    discoverer = html.escape(str(cve.get("discoverer", "Not disclosed")))

    # Safely escape affected products strings
    affected_list = cve.get("affected", [])
    if not affected_list:
        affected_str = "  • Not specified"
    else:
        affected_str = "\n".join(f"  • {html.escape(str(a))}" for a in affected_list)
    
    # Safely escape CWEs
    cwes = cve.get("cwes", [])
    cwe_str = html.escape(", ".join(str(c) for c in cwes)) if cwes else "N/A"

    # PoC logic
    if poc_found and poc_link:
        poc_str = f"✅ YES\n   🔗 {html.escape(poc_link)}"
    elif poc_found:
        poc_str = "✅ YES (Check sources for links)"
    else:
        poc_str = "❌ No public PoC found yet"

    # Reference URL compiling
    refs = cve.get("refs", [])
    refs_str = "\n".join(f"   🔗 {html.escape(str(r))}" for r in refs) if refs else "   • NVD only"

    # Core meta identifiers
    cve_id = html.escape(str(cve.get("id", "UNKNOWN-CVE")))
    published = html.escape(str(cve.get("published", "Unknown")))
    vector = html.escape(str(cve.get("vector", "N/A")))
    score_val = cve.get("score", 0.0)

    msg = f"""🚨 <b>NEW CVE ALERT</b> 🚨
━━━━━━━━━━━━━━━━━━━━━━━
🆔 <b>{cve_id}</b>
📅 Published: {published}

{emoji} <b>Severity: {score_val}/10 ({severity})</b>
<code>{bar}</code>
🔢 Vector: <code>{vector}</code>
🛡️ CWE: {cwe_str}

📦 <b>Affected Products:</b>
{affected_str}

📝 <b>Description:</b>
{desc}

💥 <b>PoC Published?</b>
{poc_str}

🔍 <b>Discovered by:</b> {discoverer}

📚 <b>Sources:</b>
{refs_str}
  🔗 https://nvd.nist.gov/vuln/detail/{cve_id}
  🔗 https://www.cve.org/CVERecord?id={cve_id}
━━━━━━━━━━━━━━━━━━━━━━━
#CVE #{severity} #BugBounty #Security"""

    return msg


def send_telegram(message: str) -> bool:
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id":    TELEGRAM_CHANNEL,
        "text":       message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = requests.post(url, json=payload, timeout=15)
        if resp.status_code == 200:
            return True
        log.error(f"Telegram error {resp.status_code}: {resp.text}")
        return False
    except Exception as e:
        log.error(f"Telegram send failed: {e}")
        return False


# ── Main Loop ──────────────────────────────────────────────────────────────────
def main():
    log.info("🚀 CVE Alert Bot starting...")
    log.info(f"   Min severity : {MIN_SEVERITY}")
    log.info(f"   Poll interval: {POLL_INTERVAL}s")
    log.info(f"   Channel      : {TELEGRAM_CHANNEL}")

    if not TELEGRAM_TOKEN or not TELEGRAM_CHANNEL:
        log.error("❌ TELEGRAM_TOKEN and TELEGRAM_CHANNEL must be set in .env")
        return

    conn = init_db()

    # Send startup message
    send_telegram(
        f"✅ <b>CVE Alert Bot is now ONLINE</b>\n"
        f"Monitoring CVEs with severity ≥ {MIN_SEVERITY}\n"
        f"Polling every {POLL_INTERVAL // 60} minutes.\n"
        f"Sources: NVD · CVE.org · GitHub PoC check"
    )

    while True:
        try:
            log.info("🔍 Checking for new CVEs...")
            vulns = fetch_recent_cves(hours_back=max(1, POLL_INTERVAL // 3600 + 1))
            new_count = 0

            for vuln in vulns:
                cve = parse_cve(vuln)
                if cve is None:
                    continue  # below threshold or no score

                if already_seen(conn, cve["id"]):
                    continue

                # Check PoC
                poc_found, poc_link = check_poc(cve["id"])
                time.sleep(1)  # be nice to GitHub API

                # Format and send
                msg = format_message(cve, poc_found, poc_link)
                if send_telegram(msg):
                    mark_seen(conn, cve["id"])
                    new_count += 1
                    log.info(f"✅ Sent: {cve['id']} (CVSS {cve['score']})")
                    time.sleep(2)  # avoid Telegram flood limits
                else:
                    log.warning(f"⚠️  Failed to send {cve['id']}")

            log.info(f"   Done. Sent {new_count} new alerts. Sleeping {POLL_INTERVAL}s...")

        except Exception as e:
            log.error(f"Main loop error: {e}", exc_info=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import requests
import sqlite3
import logging
from datetime import datetime
from urllib.parse import urlparse
import os
from dotenv import load_dotenv
from time import time
import re
import socket

# ================== CONFIG ==================

load_dotenv()

app = FastAPI(title="CyberSentinel Bot", version="5.0")

GOOGLE_API_KEY = os.getenv("AIzaSyATJ2iHbDDVeS75ZnGsrdN61BYc07HZnwA")
VT_API_KEY = os.getenv("VT_API_KEY")
SECURE_API_KEY = os.getenv("SECURE_API_KEY")

DB_FILE = os.getenv("DB_FILE", "scans.db")

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_COUNT = 10

DANGEROUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq"}
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "bank", "update", "password",
    "account", "secure", "payment", "billing"
]
DOWNLOAD_EXTENSIONS = [".exe", ".zip", ".msi", ".bat"]

logging.basicConfig(
    filename="scan_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ================== DATABASE ==================

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                user_id TEXT,
                risk TEXT,
                score INTEGER,
                findings TEXT,
                timestamp TEXT
            )
        """)

init_db()

# ================== MODELS ==================

class URLRequest(BaseModel):
    url: str
    user_id: str = "guest"

# ================== RATE LIMIT ==================

user_access_log = {}

def check_rate_limit(user_id: str):
    now = time()
    history = user_access_log.get(user_id, [])
    history = [t for t in history if now - t < RATE_LIMIT_WINDOW]

    if len(history) >= RATE_LIMIT_COUNT:
        raise HTTPException(status_code=429, detail="Too many requests")

    history.append(now)
    user_access_log[user_id] = history

# ================== UTILITIES ==================

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False

# ================== LOCAL HEURISTIC SCAN ==================

def local_scan(url: str):
    score = 0
    findings = []

    parsed = urlparse(url)
    host = parsed.hostname or ""

    # No HTTPS
    if parsed.scheme != "https":
        score += 15
        findings.append("No HTTPS")

    # IP-based domain
    try:
        socket.inet_aton(host)
        score += 15
        findings.append("IP address used as domain")
    except Exception:
        pass

    # Suspicious TLD
    if host.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 10
        findings.append("Suspicious TLD")

    # Many subdomains
    if host.count(".") >= 3:
        score += 8
        findings.append("Many subdomains")

    # Fetch page safely
    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
        html = r.text.lower()

        if len(r.history) > 3:
            score += 10
            findings.append("Multiple redirects")

        for kw in SUSPICIOUS_KEYWORDS:
            if kw in html:
                score += 5
                findings.append(f"Keyword detected: {kw}")

        for ext in DOWNLOAD_EXTENSIONS:
            if ext in html:
                score += 10
                findings.append("Executable download link")

        if re.search(r"eval\(|atob\(|document\.write", html):
            score += 15
            findings.append("Obfuscated JavaScript")

    except Exception:
        findings.append("Could not fetch content")

    return min(score, 100), findings

# ================== EXTERNAL SCANS ==================

def scan_google(url: str):
    if not GOOGLE_API_KEY:
        return False

    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
            json={
                "client": {"clientId": "cybersentinel", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=8
        )
        return "matches" in r.json()
    except Exception:
        return False

def scan_virustotal(url: str):
    if not VT_API_KEY:
        return False

    try:
        headers = {"x-apikey": VT_API_KEY}
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=8
        )
        analysis_id = submit.json()["data"]["id"]

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=8
        ).json()

        stats = report["data"]["attributes"]["stats"]
        return stats.get("malicious", 0) > 0
    except Exception:
        return False

# ================== MAIN ENDPOINT ==================

@app.post("/scan-url")
def scan_url(req: URLRequest, x_api_key: str = Header(None)):
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not is_valid_url(req.url):
        raise HTTPException(status_code=400, detail="Invalid URL")

    check_rate_limit(req.user_id)

    local_score, findings = local_scan(req.url)

    external_hit = scan_google(req.url) or scan_virustotal(req.url)
    if external_hit:
        local_score += 30

    if local_score >= DANGEROUS_THRESHOLD:
        risk = "Dangerous"
    elif local_score >= SUSPICIOUS_THRESHOLD:
        risk = "Suspicious"
    else:
        risk = "Safe"

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO scans (url, user_id, risk, score, findings, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (req.url, req.user_id, risk, local_score, ", ".join(findings), datetime.utcnow().isoformat())
        )

    logging.info("%s scanned %s → %s (%d)", req.user_id, req.url, risk, local_score)

    return {
        "url": req.url,
        "risk": risk,
        "score": local_score,
        "findings": findings
    }

# ================== RUN ==================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("Scanner:app", host="127.0.0.1", port=8000, reload=True)

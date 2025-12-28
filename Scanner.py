# main.py
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

# load .env
load_dotenv()

app = FastAPI(title="CyberSentinel Bot", version="5.0")

# config (from .env or defaults)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
SECURE_API_KEY = os.getenv("SECURE_API_KEY")
DEFAULT_EMAIL_RECEIVER = os.getenv("DEFAULT_EMAIL_RECEIVER", "admin@example.com")

RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_COUNT = int(os.getenv("RATE_LIMIT_COUNT", "10"))

LOCAL_THRESHOLD_DANGEROUS = int(os.getenv("THRESHOLD_DANGEROUS", "70"))
LOCAL_THRESHOLD_SUSPICIOUS = int(os.getenv("THRESHOLD_SUSPICIOUS", "40"))

WEIGHTS = {
    "no_https": float(os.getenv("W_NO_HTTPS", "15")),
    "ip_domain": float(os.getenv("W_IP_DOMAIN", "15")),
    "suspicious_tld": float(os.getenv("W_SUSP_TLD", "10")),
    "many_subdomains": float(os.getenv("W_SUBDOMAINS", "8")),
    "credentials_in_url": float(os.getenv("W_CREDENTIALS", "20")),
    "redirects": float(os.getenv("W_REDIRECTS", "10")),
    "suspicious_keywords": float(os.getenv("W_KEYWORDS", "12")),
    "download_links": float(os.getenv("W_DOWNLOAD", "12")),
    "obfuscated_js": float(os.getenv("W_OBFUSC_JS", "18")),
}

SUSPICIOUS_TLDS = set([t.strip().lower() for t in os.getenv("SUSPICIOUS_TLDS", "tk,ml,ga,cf,gq").split(",")])
SUSPICIOUS_KEYWORDS = [kw.strip().lower() for kw in os.getenv("SUSPICIOUS_KEYWORDS", "login,verify,confirm,bank,update,password,account,secure,payment,billing").split(",")]
DOWNLOAD_EXTENSIONS = [ext.strip().lower() for ext in os.getenv("DOWNLOAD_EXTENSIONS", ".exe,.zip,.msi,.bat,.cmd").split(",")]

DB_FILE = os.getenv("DB_FILE", "scans.db")
logging.basicConfig(filename=os.getenv("LOG_FILE", "scan_log.txt"), level=logging.INFO, format="%(asctime)s - %(message)s")

# DB init
def create_scans_table():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                user_id TEXT,
                email TEXT,
                risk TEXT,
                threats TEXT,
                score INTEGER,
                findings TEXT,
                timestamp TEXT
            );
        """)
create_scans_table()

# request model
class URLRequest(BaseModel):
    url: str
    user_id: str = "guest"
    email: str | None = None

# utilities
def is_valid_url(url: str) -> bool:
    try:
        r = urlparse(url)
        return bool(r.scheme and r.netloc)
    except Exception:
        return False

def clean_string(s: str) -> str:
    if s is None: return ""
    return re.sub(r"[^\w.@+-]", "", s)

def save_to_db(url, user_id, email, risk, threats, score, findings):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO scans (url, user_id, email, risk, threats, score, findings, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (url, user_id, email, risk, threats, score, findings, datetime.utcnow().isoformat())
            )
    except Exception as e:
        logging.error("DB error: %s", e)

def log_scan(user_id: str, url: str, risk_status: str, threats: list, score: int, findings):
    logging.info("%s scanned %s → %s | Score: %s | Threats: %s | Findings: %s", user_id, url, risk_status, score, threats, findings)

# rate limiting & caching
scan_cache: dict = {}  # url -> (g_r, g_t, v_r, v_t, local_score, findings)
user_access_log: dict = {}

def check_rate_limit(user_id: str):
    now = time()
    access_log = user_access_log.get(user_id, [])
    access_log = [t for t in access_log if now - t < RATE_LIMIT_WINDOW]
    if len(access_log) >= RATE_LIMIT_COUNT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    access_log.append(now)
    user_access_log[user_id] = access_log

# local heuristic analysis
def resolve_ip(hostname: str):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def analyze_content(html: str):
    findings = []
    if not html:
        return findings
    lower = html.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw and kw in lower:
            findings.append(("suspicious_keyword", kw))
    for ext in DOWNLOAD_EXTENSIONS:
        if ext and ext in lower:
            findings.append(("download_link", ext))
    # detect common obfuscation patterns
    if re.search(r"eval\(|atob\(|unescape\(|fromCharCode\(|document\.write\(", html, flags=re.IGNORECASE):
        findings.append(("obfuscated_js", "pattern"))
    if re.search(r"<input[^>]+type=['\"]?password['\"]?", lower):
        findings.append(("form_with_password", "present"))
    return findings

def heuristic_local_scan(url: str):
    score = 0.0
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # no https
    if parsed.scheme.lower() != "https":
        score += WEIGHTS.get("no_https", 15)
        findings.append(("no_https", "Site does not use HTTPS"))
    # domain resolves to IP or hostname is IP
    ip = None
    try:
        socket.inet_aton(hostname)
        ip = hostname
    except Exception:
        ip = resolve_ip(hostname)
    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", str(ip)):
        score += WEIGHTS.get("ip_domain", 15)
        findings.append(("ip_in_domain", f"Domain resolves to IP {ip}"))
    # suspicious tld
    tld = hostname.split(".")[-1].lower() if hostname else ""
    if tld in SUSPICIOUS_TLDS:
        score += WEIGHTS.get("suspicious_tld", 10)
        findings.append(("suspicious_tld", tld))
    # many subdomains
    if hostname.count(".") >= 3:
        score += WEIGHTS.get("many_subdomains", 8)
        findings.append(("many_subdomains", hostname))
    # credentials in URL
    if parsed.username or parsed.password or re.search(r"%3A%2F%2F.*@", url):
        score += WEIGHTS.get("credentials_in_url", 20)
        findings.append(("credentials_in_url", "URL contains credentials"))
    # long URL
    if len(url) > 200:
        score += 5
        findings.append(("long_url", str(len(url))))
    # fetch content safely
    html = ""
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        redirects = len(r.history)
        if redirects > 3:
            score += WEIGHTS.get("redirects", 10)
            findings.append(("redirect_chain", redirects))
        html = r.text
    except Exception as e:
        findings.append(("fetch_error", str(e)))
    content_findings = analyze_content(html)
    for ftype, detail in content_findings:
        if ftype == "suspicious_keyword":
            score += WEIGHTS.get("suspicious_keywords", 12)
        elif ftype == "download_link":
            score += WEIGHTS.get("download_links", 12)
        elif ftype == "obfuscated_js":
            score += WEIGHTS.get("obfuscated_js", 18)
        findings.append((ftype, detail))
    final_score = max(0, min(int(score), 100))
    return final_score, findings

# external scanners
def scan_with_google(url):
    if not GOOGLE_API_KEY:
        return "⚠️ Unknown", []
    try:
        res = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
            json={
                "client": {"clientId": "cybersentinel", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=10
        )
        data = res.json()
        if "matches" in data:
            threats = list({match.get("threatType", "UNKNOWN") for match in data["matches"]})
            return "❌ Dangerous", threats
        return "✅ Safe", []
    except Exception as e:
        logging.error("Google scan error: %s", e)
        return "⚠️ Unknown", []

def scan_with_virustotal(url):
    if not VT_API_KEY:
        return "⚠️ Unknown", []
    try:
        headers = {"x-apikey": VT_API_KEY}
        submit = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
        resp = submit.json()
        if "data" not in resp or "id" not in resp["data"]:
            return "⚠️ Unknown", []
        analysis_id = resp["data"]["id"]
        # poll once (VT may take a bit); for demo we do a single get
        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10).json()
        stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
        if stats.get("malicious", 0) > 0:
            return "❌ Dangerous", ["Malicious"]
        if stats.get("suspicious", 0) > 0:
            return "⚠️ Suspicious", ["Suspicious"]
        return "✅ Safe", []
    except Exception as e:
        logging.error("VT scan error: %s", e)
        return "⚠️ Unknown", []

THREAT_EXPLANATIONS = {
    "MALWARE": "This site may install harmful software that damages your device or steals data.",
    "SOCIAL_ENGINEERING": "This site may trick you into revealing passwords or private info.",
    "UNWANTED_SOFTWARE": "This site might offer unwanted or misleading downloads.",
    "MALICIOUS": "Detected as harmful by multiple security sources.",
    "SUSPICIOUS": "This site shows scam-like or phishing behavior.",
    "UNKNOWN": "The specific threat type couldn’t be identified."
}

def explain_threats(threats):
    return [{"type": t, "explanation": THREAT_EXPLANATIONS.get(t.upper(), "This site may be dangerous.")} for t in threats]

def get_scan_from_cache_or_api(url):
    entry = scan_cache.get(url)
    if entry:
        return entry  # (g_r, g_t, v_r, v_t, local_score, findings)
    g_r, g_t = scan_with_google(url)
    v_r, v_t = scan_with_virustotal(url)
    # local scan will be performed separately and stored later
    scan_cache[url] = (g_r, g_t, v_r, v_t, None, None)
    return scan_cache[url]

@app.post("/scan-url")
def scan_url(request: URLRequest, x_api_key: str = Header(None)):
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    if not is_valid_url(request.url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    check_rate_limit(request.user_id)

    clean_email = clean_string(request.email or DEFAULT_EMAIL_RECEIVER)
    clean_user = clean_string(request.user_id)

    # perform local heuristic
    local_score, findings = heuristic_local_scan(request.url)

    # get external scans (cached)
    cached = scan_cache.get(request.url)
    if cached and cached[4] is not None:
        # cached includes local_score and findings
        g_r, g_t, v_r, v_t, cached_local_score, cached_findings = cached
        # if local findings changed, refresh externals
        if cached_local_score != local_score or cached_findings != findings:
            g_r, g_t = scan_with_google(request.url)
            v_r, v_t = scan_with_virustotal(request.url)
            scan_cache[request.url] = (g_r, g_t, v_r, v_t, local_score, findings)
    else:
        g_r, g_t = scan_with_google(request.url)
        v_r, v_t = scan_with_virustotal(request.url)
        scan_cache[request.url] = (g_r, g_t, v_r, v_t, local_score, findings)

    # combine signals
    external_flag = "❌" if ("❌" in (g_r + v_r)) else ("⚠️" if ("⚠️" in (g_r + v_r)) else "✅")
    combined_score = min(100, local_score + (50 if external_flag == "❌" else 20 if external_flag == "⚠️" else 0))
    if combined_score >= LOCAL_THRESHOLD_DANGEROUS:
        final_risk = "❌ Dangerous"
    elif combined_score >= LOCAL_THRESHOLD_SUSPICIOUS:
        final_risk = "⚠️ Suspicious"
    else:
        final_risk = "✅ Safe"

    all_threats = (g_t or []) + (v_t or [])
    explanations = explain_threats(all_threats) if all_threats else (explain_threats(["UNKNOWN"]) if findings else [])

    save_to_db(request.url, clean_user, clean_email, final_risk, ", ".join(all_threats), combined_score, str(findings))
    log_scan(clean_user, request.url, final_risk, all_threats, combined_score, findings)

    return {
        "url": request.url,
        "local_score": local_score,
        "combined_score": combined_score,
        "final_risk": final_risk,
        "findings": findings,
        "threats": all_threats,
        "explanations": explanations,
        "sources": {
            "local": {"score": local_score, "findings": findings},
            "google": {"risk": g_r, "threats": g_t},
            "virustotal": {"risk": v_r, "threats": v_t}
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=int(os.getenv("PORT", "8000")), reload=True)

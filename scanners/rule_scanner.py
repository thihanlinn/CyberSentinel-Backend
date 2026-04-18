import re
import socket
import requests
from urllib.parse import urlparse
from fastapi import HTTPException

from config import (
    SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS, DOWNLOAD_EXTENSIONS,
    BRAND_NAMES, HIGH_RISK_PATTERNS, MEDIUM_RISK_PATTERNS,
    DANGEROUS_THRESHOLD, SUSPICIOUS_THRESHOLD
)


def is_private_ip(host):
    try:
        ip = socket.gethostbyname(host)
        return ip.startswith(("127.", "10.", "192.168.", "172."))
    except:
        return False


def is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except:
        return False


def heuristic_scan(url):
    score = 0
    findings = []

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if is_private_ip(host):
        raise HTTPException(status_code=400, detail="Private URL blocked")

    if parsed.scheme != "https":
        score += 15
        findings.append("No HTTPS encryption")

    if is_ip(host):
        score += 20
        findings.append("IP address used instead of domain name")

    if host.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 10
        findings.append("Suspicious TLD")

    if len(url) > 100:
        score += 5
        findings.append("Long URL")

    if any(k in url.lower() for k in SUSPICIOUS_KEYWORDS):
        score += 10
        findings.append("Sensitive keywords in URL")

    if any(b in url.lower() for b in BRAND_NAMES):
        score += 12
        findings.append("Potential brand impersonation")

    if any(ext in url.lower() for ext in DOWNLOAD_EXTENSIONS):
        score += 18
        findings.append("Direct executable download")

    try:
        r = requests.get(url, timeout=5, headers={"User-Agent": "CyberSentinel/12.0"})
        html = r.text.lower()

        if re.search(r"eval\(|atob\(", html):
            score += 15
            findings.append("Obfuscated JavaScript code")

        if parsed.scheme != "https" and "password" in html:
            score += 20
            findings.append("Password form submitted over insecure HTTP")

    except Exception:
        findings.append("Fetch error")

    return min(score, 100), findings


def classify(score: int, findings: list, vt_flag: bool, google_flag: bool) -> str:
    high = sum(1 for f in findings if f in HIGH_RISK_PATTERNS)
    medium = sum(1 for f in findings if f in MEDIUM_RISK_PATTERNS)

    if vt_flag or google_flag:
        return "Dangerous"

    high_count = sum(1 for f in findings if f in HIGH_RISK_PATTERNS)
    if high_count >= 1:
        return "Dangerous"

    medium_count = sum(1 for f in findings if f in MEDIUM_RISK_PATTERNS)
    if medium_count >= 2:
        return "Suspicious"

    if score >= DANGEROUS_THRESHOLD:
        return "Dangerous"
    elif score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"

    return "Safe"


def dialoger_analysis(findings: list) -> str:
    findings_lower = [f.lower() for f in findings]
    if any("password" in f for f in findings_lower):
        return "User credential risk detected"
    if any("download" in f for f in findings_lower):
        return "Potential malware delivery"
    return "No strong behavioral indicators"

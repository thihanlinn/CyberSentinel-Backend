import re
import socket
import requests
import ssl
import idna
import whois
import OpenSSL.crypto
from urllib.parse import urlparse
from fastapi import HTTPException
from datetime import datetime, UTC

from config import (
    SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS, DOWNLOAD_EXTENSIONS,
    BRAND_NAMES, HIGH_RISK_PATTERNS, MEDIUM_RISK_PATTERNS,
    DANGEROUS_THRESHOLD, SUSPICIOUS_THRESHOLD,DEFAULT_USER_AGENT, DOMAIN_NEW_DAYS, DOMAIN_YOUNG_DAYS,
    HTTP_TIMEOUT, MAX_QUERY_PARAMS, MAX_RULE_SCORE, SAFE_PORTS,
    SSL_EXPIRY_WARN_DAYS, SSL_TIMEOUT, SUBDOMAIN_WARN_COUNT,
    TRUSTED_SSL_ISSUERS, URL_LENGTH_WARN, URL_SHORTENERS,
    MAX_ALLOWED_REDIRECTS
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

def _get_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host[4:] if host.startswith("www.") else host

def _get_ssl_cert(hostname: str, port: int = 443):
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(SSL_TIMEOUT)
        try:
            pem = ssl.get_server_certificate((hostname, port))
        finally:
            socket.setdefaulttimeout(old_timeout)

        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
        not_after = datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        not_before = datetime.strptime(x509.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
        issuer = dict(x509.get_issuer().get_components())
        subject = dict(x509.get_subject().get_components())

        return {
            "expiry": not_after,
            "valid_from": not_before,
            "issuer": issuer.get(b"O", b"").decode(errors="replace"),
            "subject_cn": subject.get(b"CN", b"").decode(errors="replace"),
        }
    except Exception:
        return None

def _fetch_html(url: str):
    try:
        resp = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        return resp.text.lower(), resp
    except Exception:
        return None, None

# Leet‑speak normalisation
LEET_MAP = str.maketrans("0134578", "oieastb")
def _normalize(text: str) -> str:
    return text.lower().translate(LEET_MAP)

def heuristic_scan(url):
    score = 0
    findings = []

    parsed = urlparse(url)
    host = parsed.hostname or ""
    domain = _get_domain(url)
    path = parsed.path.lower()
    query = parsed.query.lower()

    if is_private_ip(host):
        raise HTTPException(status_code=400, detail="Private URL blocked")

    if parsed.scheme != "https":
        score += 15
        findings.append("No HTTPS encryption")

    if is_ip(host):
        score += 20
        findings.append("IP address used instead of domain name")

    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        score += 10
        findings.append(f"Suspicious TLD (.{tld})")

    subdomain_count = host.count(".") - (1 if tld else 0)
    if subdomain_count >= SUBDOMAIN_WARN_COUNT:
        score += 8
        findings.append(f"Excessive subdomains ({subdomain_count})")

    if len(url) > URL_LENGTH_WARN:
        score += 5
        findings.append("Long URL")

    try:
        ascii_encoded = host.encode("ascii")
        decoded = idna.decode(ascii_encoded)
        if decoded != host:
            score += 20
            findings.append("International domain name (possible homograph attack)")
    except (UnicodeEncodeError, idna.core.InvalidCodepoint, UnicodeError):
        pass

    norm_path = _normalize(parsed.path)
    norm_query = _normalize(parsed.query)
    norm_url = _normalize(url.lower())
    matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in norm_path or kw in norm_query or kw in norm_url]
    if matched_kw:
        score += min(15, len(matched_kw) * 3)
        findings.append(f"Sensitive keywords in URL: {', '.join(matched_kw[:3])}")

    domain_lower = domain.lower()
    for brand in BRAND_NAMES:
        if brand in domain_lower and brand not in domain_lower.split("."):
            score += 12
            findings.append(f"Potential brand impersonation ({brand})")
            break

    if parsed.port and parsed.port not in SAFE_PORTS:  # SAFE_PORTS = {80,443,8080,8443}
        score += 8
        findings.append(f"Non-standard port ({parsed.port})")

    if domain in URL_SHORTENERS:  # define URL_SHORTENERS in config
        score += 10
        findings.append("URL shortener (hides destination)")

    param_count = len(parsed.query.split("&")) if parsed.query else 0
    if param_count > MAX_QUERY_PARAMS:  # e.g. 10
        score += 5
        findings.append(f"Many query parameters ({param_count})")

    if any(ext in url.lower() for ext in DOWNLOAD_EXTENSIONS):
        score += 18
        findings.append("Direct executable download")

    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(HTTP_TIMEOUT)
        try:
            w = whois.whois(domain)
        finally:
            socket.setdefaulttimeout(old_timeout)

        creation_date = w.creation_date
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age_days = (datetime.now(UTC) - creation_date).days
            if age_days < DOMAIN_NEW_DAYS:
                score += 18
                findings.append(f"Domain registered very recently ({age_days} days ago)")
            elif age_days < DOMAIN_YOUNG_DAYS:
                score += 8
                findings.append("Domain less than 6 months old")
    except Exception:
        pass  # WHOIS failure ignored

        # 15. SSL certificate checks (only for HTTPS)
    if parsed.scheme == "https":
        cert = _get_ssl_cert(host)
        if cert:
            expiry = cert["expiry"].replace(tzinfo=UTC)
            days_left = (expiry - datetime.now(UTC)).days
            if days_left < 0:
                score += 20
                findings.append("SSL certificate expired")
            elif days_left < SSL_EXPIRY_WARN_DAYS:
                score += 10
                findings.append("SSL certificate expiring soon")

            issuer_lower = cert["issuer"].lower()
            if not any(trusted in issuer_lower for trusted in TRUSTED_SSL_ISSUERS):
                score += 5
                findings.append("SSL certificate from unusual issuer")
        else:
            score += 10
            findings.append("Unable to validate SSL certificate")

        # 16. Fetch HTML content and run content‑based checks
    html, response = _fetch_html(url)
    if html is None:
        findings.append("Timeout while fetching page content")
        score += 5
    else:
        # Redirects
        if response and len(response.history) > MAX_ALLOWED_REDIRECTS:
            score += 10
            findings.append(f"Multiple redirects ({len(response.history)})")

        # Hidden iframe (clickjacking)
        if re.search(r"<iframe[^>]*style\s*=\s*['\"].*display\s*:\s*none", html):
            score += 15
            findings.append("Hidden iframe detected (possible clickjacking)")

        # Page title keywords
        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        title = title_match.group(1).lower() if title_match else ""
        if any(kw in title for kw in SUSPICIOUS_KEYWORDS):
            score += 8
            findings.append("Suspicious keywords in page title")

        if re.search(r"eval\(|atob\(", html):
            score += 15
            findings.append("Obfuscated JavaScript code")

        if parsed.scheme != "https" and "password" in html:
            score += 20
            findings.append("Password form submitted over insecure HTTP")

    return min(score, MAX_RULE_SCORE), findings


def classify(score: int, findings: list, vt_flag: bool = False, google_flag: bool = False) -> str:

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

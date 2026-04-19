"""
Rule-based URL security scanner (19 checks).
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, UTC
from typing import Optional

import idna
import OpenSSL.crypto
import requests
import whois

from urllib.parse import urlparse
from fastapi import HTTPException

from config import (
    DEFAULT_USER_AGENT,
    DOMAIN_NEW_DAYS,
    DOMAIN_YOUNG_DAYS,
    HTTP_TIMEOUT,
    MAX_QUERY_PARAMS,
    MAX_RULE_SCORE,
    SAFE_PORTS,
    SSL_EXPIRY_WARN_DAYS,
    SSL_TIMEOUT,
    SUBDOMAIN_WARN_COUNT,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
    DOWNLOAD_EXTENSIONS,
    BRAND_NAMES,
    TRUSTED_SSL_ISSUERS,
    URL_LENGTH_WARN,
    URL_SHORTENERS,
    MAX_ALLOWED_REDIRECTS,
)

from utils.logger import get_logger

logger = get_logger("scanner.rule")


def is_private_ip(host):
    try:
        ip = socket.gethostbyname(host)
        return ip.startswith(("127.", "10.", "192.168.", "172."))
    except:
        return False


def is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False

def _get_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host[4:] if host.startswith("www.") else host


def _get_ssl_cert(hostname: str, port: int = 443) -> Optional[dict]:
    """Fetch and parse SSL certificate. Returns None on any error."""
    try:
        # ssl.get_server_certificate() does not expose a timeout kwarg in older
        # Python; wrap in socket.setdefaulttimeout for safety.
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(SSL_TIMEOUT)
        try:
            pem = ssl.get_server_certificate((hostname, port))
        finally:
            socket.setdefaulttimeout(old_timeout)

        x509     = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
        not_after  = datetime.strptime(x509.get_notAfter().decode(),  "%Y%m%d%H%M%SZ")
        not_before = datetime.strptime(x509.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
        issuer  = dict(x509.get_issuer().get_components())
        subject = dict(x509.get_subject().get_components())

        return {
            "expiry":     not_after,
            "valid_from": not_before,
            "issuer":     issuer.get(b"O",  b"").decode(errors="replace"),
            "subject_cn": subject.get(b"CN", b"").decode(errors="replace"),
        }
    except Exception as exc:
        logger.debug("SSL cert fetch failed for %s: %s", hostname, exc)
        return None


def _fetch_html(url: str) -> Optional[str]:
    """Return lowercased HTML body, or None on error."""
    try:
        resp = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        return resp.text.lower(), resp
    except requests.exceptions.Timeout:
        logger.debug("Timeout fetching content for %s", url)
        return None, None
    except Exception as exc:
        logger.debug("Content fetch failed for %s: %s", url, exc)
        return None, None

LEET_MAP = str.maketrans("0134578", "oieastb")

def _normalize(text: str) -> str:
    """Translate common leet-speak substitutions before keyword matching."""
    return text.lower().translate(LEET_MAP)

class RuleScanner:
    @staticmethod
    def scan(url: str) -> tuple[int, list[str]]:
        score:    int       = 0
        findings: list[str] = []

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
            ascii_encoded = host.encode("ascii")   # raises UnicodeEncodeError for non-ASCII
            decoded = idna.decode(ascii_encoded)
            if decoded != host:
                score += 20
                findings.append("International domain name (possible homograph attack)")
        except (UnicodeEncodeError, idna.core.InvalidCodepoint, UnicodeError):
            pass

        norm_path = _normalize(path)
        norm_query = _normalize(query)
        norm_url = _normalize(url.lower())
        matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in norm_path or kw in norm_query or kw in norm_url]
        if matched_kw:
            score += min(15, len(matched_kw) * 3)
            findings.append(f"Sensitive keywords in URL: {', '.join(matched_kw[:3])}")

        for brand in BRAND_NAMES:
            parts = domain.lower().split(".")
            if brand in domain.lower() and brand not in parts:
                score += 12
                findings.append(f"Potential brand impersonation ({brand})")
                break

        if parsed.port and parsed.port not in SAFE_PORTS:
            score += 8
            findings.append(f"Non-standard port ({parsed.port})")

        if domain in URL_SHORTENERS:
            score += 10
            findings.append("URL shortener (hides destination)")

        param_count = len(parsed.query.split("&")) if parsed.query else 0
        if param_count > MAX_QUERY_PARAMS:
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
                # Use naive UTC to avoid tz-aware comparison TypeError
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
            pass  # WHOIS may fail; not a hard error

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

        html, response = _fetch_html(url)
        if html is None:
            findings.append("Timeout while fetching page content")
            score += 5
        else:
            if response and len(response.history) > MAX_ALLOWED_REDIRECTS:
                score += 10
                findings.append(f"Multiple redirects ({len(response.history)})")

            if re.search(r"<iframe[^>]*style\s*=\s*['\"].*display\s*:\s*none", html):
                score += 15
                findings.append("Hidden iframe detected (possible clickjacking)")

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


    def dialoger_analysis(findings: list) -> str:
        findings_lower = [f.lower() for f in findings]
        if any("password" in f for f in findings_lower):
            return "User credential risk detected"
        if any("download" in f for f in findings_lower):
            return "Potential malware delivery"
        return "No strong behavioral indicators"

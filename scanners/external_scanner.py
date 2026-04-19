"""
Google Safe Browsing & VirusTotal integrations.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from utils.logger import get_logger
from config import VT_API_KEY, VT_TIMEOUT, GOOGLE_API_KEY, HTTP_TIMEOUT

logger = get_logger("scanner.external")


@dataclass
class ExternalResult:
    flagged: bool
    message: str

class ExternalScanner:

    @staticmethod
    async def check_virustotal(url: str) -> ExternalResult:
        if not VT_API_KEY:
            return ExternalResult(False, "VirusTotal API key not configured")

        try:
            headers = {"x-apikey": VT_API_KEY}

            async with httpx.AsyncClient(timeout=VT_TIMEOUT) as client:
                submit = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                )

                if submit.status_code != 200:
                    return ExternalResult(False, "VirusTotal submission failed")

                analysis_id: str = submit.json()["data"]["id"]

                report_resp = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                )
                report_resp.raise_for_status()
                stats = report_resp.json()["data"]["attributes"]["stats"]

            malicious: int = stats.get("malicious", 0)
            if malicious > 0:
                return ExternalResult(True, f"Flagged by {malicious} VirusTotal vendors")
            return ExternalResult(False, f"Clean ({stats.get('harmless', 0)} vendors OK)")

        except Exception as e:
            logger.warning(f"VirusTotal error: {e}")
            return ExternalResult(False, f"VirusTotal error: {str(e)[:80]}")

    @staticmethod
    async def check_google_safebrowsing(url: str) -> ExternalResult:
        if not GOOGLE_API_KEY:
            return ExternalResult(False, "Google API key not configured")

        payload = {
            "client": {"clientId": "cybersentinel", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                resp = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()

            if "matches" in data:
                threats = [m["threatType"] for m in data["matches"]]
                return ExternalResult(True, f"Blocked by Google: {', '.join(threats)}")

            return ExternalResult(False, "Not in Google blacklist")

        except Exception as e:
            logger.warning(f"Google Safe Browsing error: {e}")
            return ExternalResult(False, f"Google API error: {str(e)[:80]}")

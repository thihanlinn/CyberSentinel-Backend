import time
import requests
from utils.logger import logger
from config import VT_API_KEY, GOOGLE_API_KEY


def check_virustotal(url: str):
    if not VT_API_KEY:
        return {"used": False, "score": 0, "malicious": False}

    try:
        headers = {"x-apikey": VT_API_KEY}

        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        r.raise_for_status()
        analysis_id = r.json()["data"]["id"]

        time.sleep(2)

        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        r2.raise_for_status()
        stats = r2.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        score = min(malicious * 20 + suspicious * 10, 60)
        return {"used": True, "score": score, "malicious": malicious > 0}

    except Exception as e:
        logger.warning(f"VirusTotal error: {e}")
        return {"used": True, "score": 0, "malicious": False}


def check_google_safe(url: str):
    if not GOOGLE_API_KEY:
        return {"used": False, "score": 0, "malicious": False}

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

        body = {
            "client": {"clientId": "cybersentinel", "clientVersion": "12.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        r = requests.post(endpoint, json=body)
        r.raise_for_status()
        data = r.json()

        if "matches" in data:
            return {"used": True, "score": 60, "malicious": True}
        return {"used": True, "score": 0, "malicious": False}

    except Exception as e:
        logger.warning(f"Google Safe Browsing error: {e}")
        return {"used": True, "score": 0, "malicious": False}


def fuse_scores(local_score: int, vt_result: dict, google_result: dict):
    api_score = 0
    api_used = False

    if vt_result["used"]:
        api_used = True
        api_score += vt_result["score"]

    if google_result["used"]:
        api_used = True
        api_score += google_result["score"]

    final_score = min(local_score + api_score, 100)
    return final_score, api_used

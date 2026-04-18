import time
from fastapi import FastAPI, Header, HTTPException, Request

from config import SECURE_API_KEY, RATE_LIMIT_WINDOW, RATE_LIMIT_COUNT
from models import URLRequest
from database import init_db, get_cached_result, save_result, get_recent_logs
from scanners.rule_scanner import heuristic_scan, classify, dialoger_analysis
from scanners.external_scanner import check_virustotal, check_google_safe, fuse_scores
from utils.logger import logger

# APP 

app = FastAPI(title="CyberSentinel", version="12.0")

init_db()

# RATE LIMIT

user_requests: dict = {}


def check_rate_limit(user_id):
    now = time.time()

    if user_id not in user_requests:
        user_requests[user_id] = []

    user_requests[user_id] = [
        t for t in user_requests[user_id]
        if now - t < RATE_LIMIT_WINDOW
    ]

    if len(user_requests[user_id]) >= RATE_LIMIT_COUNT:
        raise HTTPException(status_code=429, detail="Too many requests")

    user_requests[user_id].append(now)


# VALIDATION

def is_valid_url(url):
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.scheme in ["http", "https"] and parsed.netloc
    except:
        return False


# ENDPOINTS

@app.post("/scan-url")
async def scan(req: URLRequest, request: Request, x_api_key: str = Header(None)):
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not is_valid_url(req.url):
        raise HTTPException(status_code=400, detail="Invalid URL")

    check_rate_limit(req.user_id)

    cached = get_cached_result(req.url)
    if cached:
        return {
            "url": req.url,
            "cached": True,
            "risk": cached["risk"],
            "score": cached["score"],
            "findings": cached["findings"]
        }

    local_score, findings = heuristic_scan(req.url)

    vt_result = check_virustotal(req.url)
    google_result = check_google_safe(req.url)

    final_score, api_used = fuse_scores(local_score, vt_result, google_result)

    reasoning = dialoger_analysis(findings)

    risk = classify(final_score, findings,
                    vt_result["malicious"], google_result["malicious"])

    save_result(req.url, req.user_id, final_score, risk, findings,
                vt_result["malicious"], google_result["malicious"])

    logger.info(f"Scanned {req.url} -> {risk} (score={final_score})")

    return {
        "url": req.url,
        "risk": risk,
        "local_score": local_score,
        "final_score": final_score,
        "findings": findings,
        "dialoger": reasoning,
        "api_used": api_used,
        "virustotal": {
            "used": vt_result["used"],
            "malicious": vt_result["malicious"],
            "score": vt_result["score"]
        },
        "google_safe": {
            "used": google_result["used"],
            "malicious": google_result["malicious"],
            "score": google_result["score"]
        }
    }


@app.get("/admin/logs")
async def get_logs(x_api_key: str = Header(None)):
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return {"logs": get_recent_logs()}


@app.get("/")
async def home():
    return {"message": "CyberSentinel Fusion Scanner Running"}


#   RUN  

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

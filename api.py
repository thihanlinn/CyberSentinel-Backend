"""
FastAPI application entry point.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from time import monotonic

from fastapi import FastAPI, Header, HTTPException

from config import (
    DANGEROUS_THRESHOLD,
    EXTERNAL_BOOST,
    ML_WEIGHT,
    RATE_LIMIT_COUNT,
    RATE_LIMIT_WINDOW,
    RULE_WEIGHT,
    SECURE_API_KEY,
    ADMIN_API_KEY,
    SUSPICIOUS_THRESHOLD,
    HIGH_RISK_PATTERNS,
    MEDIUM_RISK_PATTERNS,
    FEATURE_DESCRIPTIONS,
)
from models import URLRequest, FeedbackRequest, FeedbackResponse, ScanResponse
from database import db
from scanners.rule_scanner import RuleScanner
from scanners.external_scanner import ExternalScanner
from scanners.ml_scanner import MLScanner
from utils.logger import get_logger

logger = get_logger("scanner.api")

#  Singletons initialised once ─
ml_scanner   = MLScanner()
rule_scanner = RuleScanner()

#  Rate-limit store (user_id → list[timestamp]) ─
# For a multi-worker deployment replace with a Redis-backed solution.
_rate_store: dict[str, list[float]] = {}
_rate_lock = asyncio.Lock()


#  Application lifespan

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Open DB on startup, close on shutdown — no top-level blocking calls.
    await db.connect()
    logger.info("CyberSentinel API started")
    yield
    await db.close()
    logger.info("CyberSentinel API stopped")


# APP
app = FastAPI(
    title="CyberSentinel",
    version="2.0",
    lifespan = lifespan,
)

# Auth helper
# Raise 401 if the provided key doesn't match SECURE_API_KEY."""
def _require_api_key(x_api_key: str | None) -> None:
    if not SECURE_API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

def _require_admin_api_key(x_api_key: str | None) -> None:
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin API key")


# RATE LIMIT

async def check_rate_limit(user_id: str) -> None:
    now = monotonic()
    async with _rate_lock:
        timestamps = _rate_store.get(user_id, [])
        # Evict expired windows
        timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if len(timestamps) >= RATE_LIMIT_COUNT:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        timestamps.append(now)
        _rate_store[user_id] = timestamps


#  Explanation helper

def generate_explanation(risk: str, findings: list[str]) -> str:
    if risk == "Dangerous":
        return f"High risk: {'; '.join(findings[:3])}"
    if risk == "Suspicious":
        return f"Medium risk: {'; '.join(findings[:2])}"
    return "Low risk: Appears safe"


# Risk classification
# Determines risk label using external flags, named pattern counts, and score.

def classify(
    score: int,
    findings: list[str],
    vt_flagged: bool,
    google_flagged: bool,
) -> str:
    # External feeds take priority
    if vt_flagged or google_flagged:
        return "Dangerous"

    high_count   = sum(1 for f in findings if f in HIGH_RISK_PATTERNS)
    medium_count = sum(1 for f in findings if f in MEDIUM_RISK_PATTERNS)

    if high_count >= 1:
        return "Dangerous"
    if medium_count >= 2:
        return "Suspicious"

    # Fall back to score thresholds
    if score >= DANGEROUS_THRESHOLD:
        return "Dangerous"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"


# ML Explanation Humanizer
# Convert ML feature explanations into human-readable text.

def format_ml_explanation(explanations: list[dict]) -> str:
    formatted = []

    for e in explanations:
        feature = e.get("feature")
        impact = e.get("impact", 0) * 100

        description = FEATURE_DESCRIPTIONS.get(feature)

        # Handle dynamic keyword features
        if description is None and feature.startswith("kw_"):
            keyword = feature.replace("kw_", "")
            template = FEATURE_DESCRIPTIONS.get(
                "kw_*", "the suspicious keyword '{keyword}' appearing in the URL"
            )
            description = template.format(keyword=keyword)

        # Fallback
        if description is None:
            description = feature.replace("_", " ")

        formatted.append(
            f"This URL contains {description} with {impact:.2f}% influence on the prediction."
        )

    return " ".join(formatted)


# ENDPOINTS

@app.post("/scan-url", response_model=ScanResponse)
async def scan_url(
        req: URLRequest,
        x_api_key: str | None = Header(default=None),
) -> Any:
    _require_api_key(x_api_key)
    await check_rate_limit(req.user_id)

    logger.info("Scanning URL '%s' for user '%s'", req.url, req.user_id)

    cached = await db.get_cached_scan(req.url)
    if cached:
        logger.info("Cache hit for '%s'", req.url)
        return {**cached, "cached": True}

    # Rule-based and ML scans
    rule_score, findings = RuleScanner.scan(req.url)
    ml_result = ml_scanner.predict(req.url)

    # External checks concurrently
    google_result, vt_result = await asyncio.gather(
        ExternalScanner.check_google_safebrowsing(req.url),
        ExternalScanner.check_virustotal(req.url),
    )

    # Append external messages to findings (skip error messages)
    for msg in (google_result.message, vt_result.message):
        if "error" not in msg.lower():
            findings.append(msg)

    #  Score fusion
    ml_score = ml_result.score if not ml_result.error else 0.0
    if ml_result.error:
        final_score = rule_score  # ML unavailable → trust rule score fully
    else:
        final_score = int(rule_score * RULE_WEIGHT + ml_score * ML_WEIGHT)
    if google_result.flagged or vt_result.flagged:
        final_score = min(100, final_score + EXTERNAL_BOOST)

    findings.append(f"ML Analysis: {ml_result.label} ({ml_score:.2f}/100)")

    #  Classification (pattern-aware)
    risk = classify(final_score, findings,
                    vt_result.flagged, google_result.flagged)

    #  Dialoger reasoning
    dialoger = RuleScanner.dialoger_analysis(findings)

    #  Persist to database
    await db.save_scan(
        url=req.url,
        user_id=req.user_id,
        risk=risk,
        rule_score=rule_score,
        ml_score=int(ml_score),
        final_score=final_score,
        ml_prediction=ml_result.label,
        external_checks=dict(
            google_safe_browsing=(not google_result.flagged
                                  if "error" not in google_result.message.lower()
                                  else "error"),
            virustotal=(not vt_result.flagged
                        if "error" not in vt_result.message.lower()
                        else "error"),
        ),
        findings=findings,
        explanation=generate_explanation(risk, findings),
        dialoger=dialoger,
        ml_explanation=format_ml_explanation(ml_result.explanation),
    )

    logger.info(
        "Scan complete — user=%s url=%s risk=%s score=%d dialoger=%s",
        req.user_id, req.url, risk, final_score, dialoger,
    )

    return ScanResponse(
        url=req.url,
        risk=risk,
        scores=dict(rule_based=rule_score, ml_based=ml_score, final=final_score),
        ml_prediction = ml_result.label,
        external_checks = dict(
            google_safe_browsing=(not google_result.flagged
                                  if "error" not in google_result.message.lower()
                                  else "error"),
            virustotal=(not vt_result.flagged
                        if "error" not in vt_result.message.lower()
                        else "error"),
        ),
        findings=findings,
        explanation=generate_explanation(risk, findings),
        dialoger=dialoger,
        ml_explanation=format_ml_explanation(ml_result.explanation),
    )

@app.post("/provide-feedback", response_model=FeedbackResponse)
async def provide_feedback(
    req: FeedbackRequest,
    x_api_key: str | None = Header(default=None),
) -> FeedbackResponse:
    _require_api_key(x_api_key)

    await db.save_feedback(
        url            = req.url,
        predicted_risk = (await db.get_cached_scan(req.url) or {}).get("risk", "unknown"),
        actual_risk    = req.actual_risk,
        feedback       = req.feedback,
    )

    logger.info("Feedback saved for '%s' → actual_risk=%s", req.url, req.actual_risk)
    return FeedbackResponse(status="success", message="Feedback received")

@app.get("/admin/logs")
async def admin_logs(
        x_api_key: str  | None = Header(default=None),
) -> dict:
    _require_admin_api_key(x_api_key)
    logs = await db.get_recent_logs()
    return {"logs": logs}

@app.get("/admin/feedback")
async def admin_feedback(
        x_api_key: str  | None = Header(default=None),
) -> dict:
    _require_admin_api_key(x_api_key)
    feedbacks = await db.get_feedbacks()
    return {"feedback": feedbacks}


@app.get("/")
async def home() -> dict:
    return {"message": "CyberSentinel running"}


#   RUN  

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )

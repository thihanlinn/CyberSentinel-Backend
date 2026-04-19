"""
Pydantic request and response schemas
"""

from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, field_validator


class URLRequest(BaseModel):
    url: str
    user_id: str = "guest"

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        # Only allow http/https to prevent path-injection via file:// etc.
        v = v.strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        # Basic sanity: must have a netloc after stripping scheme
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if not parsed.netloc:
            raise ValueError("URL is missing a valid host")
        return v


class FeedbackRequest(BaseModel):
    url: str
    actual_risk: Literal["Safe", "Suspicious", "Dangerous"]
    feedback: str = ""


# Response shapes

class ScoreBreakdown(BaseModel):
    rule_based: int
    ml_based:   float
    final:      int


class ExternalChecks(BaseModel):
    google_safe_browsing: bool | str
    virustotal:           bool | str


class ScanResponse(BaseModel):
    url:             str
    risk:            Literal["Safe", "Suspicious", "Dangerous"]
    scores:          ScoreBreakdown
    ml_prediction:   str
    external_checks: ExternalChecks
    findings:        list[str]
    explanation:     str
    dialoger:        str = "No strong behavioral indicators"
    ml_explanation:  str


class FeedbackResponse(BaseModel):
    status:  str
    message: str
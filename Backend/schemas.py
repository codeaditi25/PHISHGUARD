"""
LinkShield - Pydantic Schemas

Purpose:
    Define and validate the data exchanged between
    the frontend and FastAPI.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import (
    BaseModel,
    Field,
)


# =========================================================
# INDIVIDUAL SECURITY CHECK
# =========================================================

class SecurityCheck(BaseModel):
    name: str
    status: str
    score: int = Field(
        ge=0,
        description="Risk points contributed by this check",
    )
    reason: str
    severity: str = Field(
        default="INFO",
        description="INFO, LOW, MEDIUM, HIGH, or CRITICAL",
    )
    category: str = Field(
        default="general",
        description="Signal group used by the correlation engine",
    )


# =========================================================
# URL ANALYSIS REQUEST
# =========================================================

class URLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL to analyze",
    )


# =========================================================
# ANALYSIS RESPONSE
# =========================================================

class AnalysisResponse(BaseModel):
    url: str
    score: int = Field(
        ge=0,
        le=100,
        description="Final hybrid risk score (0-100)",
    )
    verdict: str
    summary: str
    checks: List[SecurityCheck]
    rule_score: Optional[int] = Field(
        default=None,
        description="Heuristic rule-based risk score (0-100)",
    )
    ml_score: Optional[int] = Field(
        default=None,
        description="Machine Learning model risk score (0-100)",
    )
    ml_probability: Optional[float] = Field(
        default=None,
        description="Machine Learning predicted phishing probability (0.0-1.0)",
    )
    ml_details: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Detailed ML classification metadata and feature signals",
    )


# =========================================================
# STORED SCAN RESPONSE
# =========================================================

class ScanResponse(BaseModel):
    id: int
    url: str
    score: int
    verdict: str
    created_at: datetime

    class Config:
        from_attributes = True

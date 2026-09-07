"""
LinkShield - Pydantic Schemas

Purpose:
    Define and validate the data exchanged between
    the frontend and FastAPI.

Schemas are NOT database tables.

They describe API requests and responses.
"""

from datetime import datetime

from typing import List

from pydantic import (
    BaseModel,
    Field,
)


# =========================================================
# INDIVIDUAL SECURITY CHECK
# =========================================================

class SecurityCheck(BaseModel):
    """
    Represents one result produced by the analysis engine.

    Example:

    {
        "name": "HTTPS",
        "status": "safe",
        "score": 0,
        "reason": "The website uses HTTPS."
    }
    """

    name: str

    status: str

    score: int = Field(
        ge=0,
        description="Risk points contributed by this check",
    )

    reason: str


# =========================================================
# URL ANALYSIS REQUEST
# =========================================================

class URLRequest(BaseModel):
    """
    Data received from the frontend.

    Expected JSON:

    {
        "url": "https://example.com"
    }
    """

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
    """
    Complete response returned to the frontend.

    Example:

    {
        "url": "https://example.com",
        "score": 15,
        "verdict": "Safe",
        "checks": [...]
    }
    """

    url: str

    score: int = Field(
        ge=0,
        le=100,
    )

    verdict: str

    checks: List[SecurityCheck]


# =========================================================
# STORED SCAN RESPONSE
# =========================================================

class ScanResponse(BaseModel):
    """
    Represents a scan record when it is retrieved
    from the database.
    """

    id: int

    url: str

    score: int

    verdict: str

    created_at: datetime

    class Config:
        """
        Allows Pydantic to create this schema from
        a SQLAlchemy model.
        """

        from_attributes = True
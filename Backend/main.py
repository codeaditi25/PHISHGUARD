"""
LinkShield - FastAPI Main Application

Purpose:
    Start the FastAPI application and provide the API routes.

Main route:
    POST /analyze

Additional routes:
    GET /
    GET /health
    GET /scans
"""


from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
)

from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from urllib.parse import urlparse


# =========================================================
# PROJECT IMPORTS
# =========================================================

from config import (
    APP_NAME,
    APP_VERSION,
    CORS_ORIGINS,
)

from database import (
    get_db,
    create_tables,
)

from models import Scan

from schemas import (
    URLRequest,
    AnalysisResponse,
    ScanResponse,
)

from analysis.url_parser import parse_url

from analysis.security_checks import (
    run_security_checks,
)

from analysis.scoring import (
    create_analysis_result,
)


# =========================================================
# CREATE FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title=APP_NAME,

    description=(
        "LinkShield URL phishing and fraud "
        "risk analysis API"
    ),

    version=APP_VERSION,
)


# =========================================================
# CORS
# =========================================================

"""
Allows the frontend to communicate with FastAPI.

Development:
    frontend → port 5500
    backend  → port 8000

Production:
    Restrict this to the real frontend domain.
"""

app.add_middleware(
    CORSMiddleware,

    allow_origins=CORS_ORIGINS,

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

"""
Create database tables when the application starts.

The Scan table comes from models.py.
"""

create_tables()


# =========================================================
# ROOT ROUTE
# =========================================================

@app.get("/")
def root():
    """
    Basic endpoint used to confirm that LinkShield
    backend is running.
    """

    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health_check():
    """
    Simple health endpoint.

    Useful for checking whether the API is alive.
    """

    return {
        "status": "healthy"
    }


# =========================================================
# ANALYZE URL
# =========================================================

@app.post(
    "/analyze",
    response_model=AnalysisResponse,
)
def analyze_url(
    request: URLRequest,

    db: Session = Depends(get_db),
):
    """
    Analyze a submitted URL.

    Complete flow:

        Frontend
            ↓
        URLRequest
            ↓
        Parse URL
            ↓
        Security Checks
            ↓
        Risk Scoring
            ↓
        Save Scan
            ↓
        Return AnalysisResponse
    """

    # -----------------------------------------------------
    # Clean input
    # -----------------------------------------------------

    url = request.url.strip()


    if not url:

        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty.",
        )


    # -----------------------------------------------------
    # Add scheme when user enters only a domain
    # -----------------------------------------------------

    """
    Example:

        google.com

    becomes:

        https://google.com

    This is only normalization.
    We do NOT visit the website.
    """

    if not urlparse(url).scheme:

        analysis_url = (
            "https://" + url
        )

    else:

        analysis_url = url


    # -----------------------------------------------------
    # Parse URL
    # -----------------------------------------------------

    try:

        parsed = parse_url(
            analysis_url
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail="Invalid URL format.",
        )


    # -----------------------------------------------------
    # Validate hostname
    # -----------------------------------------------------

    hostname = parsed.get(
        "hostname"
    )


    if not hostname:

        raise HTTPException(
            status_code=400,
            detail=(
                "The URL does not contain "
                "a valid hostname."
            ),
        )


    # -----------------------------------------------------
    # Run security analysis
    # -----------------------------------------------------

    checks = run_security_checks(
        analysis_url,
        parsed,
    )


    # -----------------------------------------------------
    # Calculate score + verdict
    # -----------------------------------------------------

    result = create_analysis_result(
        analysis_url,
        checks,
    )


    # -----------------------------------------------------
    # Save scan to database
    # -----------------------------------------------------

    scan = Scan(
        url=result["url"],

        score=result["score"],

        verdict=result["verdict"],
    )


    db.add(scan)

    db.commit()

    db.refresh(scan)


    # -----------------------------------------------------
    # Return result to frontend
    # -----------------------------------------------------

    return result


# =========================================================
# SCAN HISTORY
# =========================================================

@app.get(
    "/scans",
    response_model=list[ScanResponse],
)
def get_scan_history(
    db: Session = Depends(get_db),
):
    """
    Return previous URL scans.

    This can later be used to build a
    "Recent Scans" page in the frontend.
    """

    scans = (
        db.query(Scan)
        .order_by(
            Scan.created_at.desc()
        )
        .limit(50)
        .all()
    )

    return scans


# =========================================================
# RUN DEVELOPMENT SERVER
# =========================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",

        host="127.0.0.1",

        port=8000,

        reload=True,
    )
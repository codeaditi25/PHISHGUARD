"""
LinkShield - Risk Scoring Engine

Purpose:
    Combine the results of individual security checks
    into one normalized risk score and final verdict.

Score range:
    0  = lowest detected risk
    100 = highest detected risk

Important:
    A score is an indicator, not absolute proof that
    a website is malicious.
"""


# =========================================================
# SCORE LIMIT
# =========================================================

MAX_SCORE = 100


# =========================================================
# VERDICT THRESHOLDS
# =========================================================

# 0 - 29     → Safe
# 30 - 69    → Suspicious
# 70 - 100   → Potentially Dangerous

SAFE_THRESHOLD = 30
DANGEROUS_THRESHOLD = 70


# =========================================================
# CALCULATE SCORE
# =========================================================

def calculate_score(checks: list) -> int:
    """
    Add the individual risk contributions.

    Each security check already contains its own score.

    Example:

        HTTPS          → 0
        IP address     → 20
        Keywords       → 7
        @ symbol       → 20

        Total          → 47
    """

    total = 0

    for check in checks:

        # Make sure malformed values cannot crash scoring.
        try:
            score = int(check.get("score", 0))
        except (ValueError, TypeError):
            score = 0

        total += max(0, score)

    # Never allow the final score above 100.
    return min(total, MAX_SCORE)


# =========================================================
# DETERMINE VERDICT
# =========================================================

def get_verdict(score: int) -> str:
    """
    Convert the numerical score into a human-readable verdict.
    """

    if score < SAFE_THRESHOLD:
        return "Safe"

    if score < DANGEROUS_THRESHOLD:
        return "Suspicious"

    return "Potentially Dangerous"


# =========================================================
# CREATE COMPLETE ANALYSIS
# =========================================================

def create_analysis_result(url: str, checks: list) -> dict:
    """
    Create the final response that FastAPI sends to the frontend.

    The structure is intentionally compatible with results.js.
    """

    score = calculate_score(checks)

    verdict = get_verdict(score)

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "checks": checks,
    }
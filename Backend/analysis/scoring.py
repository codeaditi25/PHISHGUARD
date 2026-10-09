"""
LinkShield - Hybrid Risk Scoring Engine (Rules + ML)

Purpose:
    Combine the results of individual heuristic checks and the trained
    Machine Learning classifier into one normalized hybrid risk score
    and verdict.

Score range:
    0  = lowest detected risk
    100 = highest detected risk

Hybrid formulation:
    final_score = round(0.5 * rule_score + 0.5 * ml_score)
"""

MAX_SCORE = 100

SAFE_THRESHOLD = 30
DANGEROUS_THRESHOLD = 70


def calculate_score(checks: list) -> int:
    """
    Add individual heuristic check scores.
    """
    total = 0

    for check in checks:
        try:
            score = int(check.get("score", 0))
        except (ValueError, TypeError):
            score = 0

        total += max(0, score)

    return min(total, MAX_SCORE)


def get_verdict(score: int) -> str:
    """
    Convert numerical score into human-readable verdict.
    """
    if score < SAFE_THRESHOLD:
        return "Safe"
    if score < DANGEROUS_THRESHOLD:
        return "Suspicious"
    return "Potentially Dangerous"


def create_analysis_result(
    url: str,
    checks: list,
    ml_prob: float = None,
    ml_details: dict = None,
) -> dict:
    """
    Create the hybrid analysis result combining Rule-based and AI/ML detection.
    """
    rule_score = calculate_score(checks)

    if ml_prob is not None:
        # Scale ML probability (0.0 - 1.0) to 0 - 100
        ml_score = int(round(ml_prob * 100))
        # 50/50 blend between deterministic heuristic rules and adaptive ML model
        final_score = int(round(0.5 * rule_score + 0.5 * ml_score))
        final_score = min(MAX_SCORE, max(0, final_score))
    else:
        ml_score = None
        final_score = rule_score

    verdict = get_verdict(final_score)

    if ml_prob is not None:
        summary = (
            f"Hybrid Security Score: {final_score}/100 ({verdict}). "
            f"Rule-based Heuristics: {rule_score}/100, AI/ML Classifier Risk: {ml_score}/100."
        )
    else:
        summary = f"Rule-based Risk Score: {final_score}/100 ({verdict})."

    return {
        "url": url,
        "score": final_score,
        "verdict": verdict,
        "summary": summary,
        "rule_score": rule_score,
        "ml_score": ml_score,
        "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
        "ml_details": ml_details or {},
        "checks": checks,
    }
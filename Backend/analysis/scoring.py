"""
LinkShield - Hybrid Risk Scoring Engine (Correlation Rules + AI/ML)

Purpose:
    Combine the results of individual heuristic checks (with correlation escalation)
    and the trained Machine Learning classifier into one normalized hybrid risk score
    and verdict.

Score range:
    0  = lowest detected risk
    100 = highest detected risk

Hybrid formulation:
    final_score = round(0.5 * rule_score + 0.5 * ml_score)
"""

from typing import List, Dict, Any, Optional

MAX_SCORE = 100
VERDICTS = (
    (20, "Low Risk"),
    (40, "Caution"),
    (60, "Suspicious"),
    (80, "High Risk"),
    (101, "Critical / Likely Phishing"),
)


def make_escalation(severity: str, score: int, reason: str) -> dict:
    return {
        "name": "Correlated Phishing Signals",
        "status": "danger" if severity in {"HIGH", "CRITICAL"} else "warning",
        "severity": severity,
        "score": score,
        "reason": reason,
        "category": "correlation",
    }


def apply_correlation_rules(checks: List[dict]) -> List[dict]:
    """Add explicit bonuses for combinations that are worse than their parts."""
    names = {check["name"] for check in checks if check.get("score", 0) > 0}
    bonuses: List[dict] = []

    def add_if(condition: bool, severity: str, score: int, reason: str) -> None:
        if condition:
            bonuses.append(make_escalation(severity, score, reason))

    has = lambda name: name in names
    has_sensitive = has("Sensitive Action Pattern")
    has_keywords = has("Suspicious Keywords")

    add_if(has("Protocol") and has_sensitive, "HIGH", 12, "An unencrypted connection is combined with a credential or payment request.")
    add_if(has("IP Address Domain") and has_sensitive, "CRITICAL", 20, "An IP-address host is combined with a sensitive action request.")
    add_if(has("URL @ Symbol") and has_sensitive, "CRITICAL", 20, "Destination-hiding @ syntax is combined with a sensitive action request.")
    add_if(has("Brand Impersonation") and has_sensitive, "CRITICAL", 25, "Brand impersonation is combined with a credential or payment request.")
    add_if(has("Unicode / Homoglyph") and has("Brand Impersonation"), "CRITICAL", 25, "Unicode/Punycode and brand impersonation occur together.")
    add_if(has("URL Shortener") and (has("Encoding / Obfuscation") or has_sensitive), "HIGH", 15, "A shortened URL hides a redirect, encoded destination, or sensitive action.")
    add_if(has("Subdomain Depth") and has_keywords, "HIGH", 12, "Excessive subdomains are combined with suspicious credential or payment wording.")
    add_if(has("Encoding / Obfuscation") and has_sensitive, "HIGH", 12, "Encoded or redirect-like data is combined with a sensitive action request.")

    high_or_critical = sum(check.get("severity") in {"HIGH", "CRITICAL"} and check.get("score", 0) > 0 for check in checks)
    medium = sum(check.get("severity") == "MEDIUM" and check.get("score", 0) > 0 for check in checks)

    if high_or_critical >= 4:
        bonuses.append(make_escalation("CRITICAL", 30, "Four or more high-severity phishing indicators were detected together."))
    elif high_or_critical >= 3:
        bonuses.append(make_escalation("CRITICAL", 20, "Multiple high-severity phishing indicators were detected together."))
    elif high_or_critical >= 2:
        bonuses.append(make_escalation("HIGH", 12, "Two high-severity phishing indicators were detected together."))
    elif medium >= 3 and not bonuses:
        bonuses.append(make_escalation("HIGH", 12, "Several medium-severity phishing indicators were detected together."))

    return checks + bonuses


def calculate_score(checks: List[dict]) -> int:
    """Add individual heuristic check scores."""
    total = 0
    for check in checks:
        try:
            total += max(0, int(check.get("score", 0)))
        except (ValueError, TypeError):
            continue
    return min(total, MAX_SCORE)


def get_verdict(score: int, checks: List[dict]) -> str:
    """Apply severity floors so critical/high signals are properly weighted."""
    critical = sum(check.get("severity") == "CRITICAL" and check.get("score", 0) > 0 for check in checks)
    high = sum(check.get("severity") == "HIGH" and check.get("score", 0) > 0 for check in checks)
    medium = sum(check.get("severity") == "MEDIUM" and check.get("score", 0) > 0 for check in checks)

    if critical >= 2:
        return "Critical / Likely Phishing"
    if critical >= 1:
        return "High Risk" if score < 80 else "Critical / Likely Phishing"
    if high >= 2:
        return "Suspicious" if score < 60 else "High Risk"
    if high >= 1 or medium >= 3:
        return "Caution" if score < 40 else "Suspicious"
    if medium >= 1:
        return "Caution"

    for upper_bound, verdict in VERDICTS:
        if score < upper_bound:
            return verdict

    return "Critical / Likely Phishing"


def build_summary(verdict: str, checks: List[dict], ml_prob: Optional[float] = None) -> str:
    concerning = [check["reason"] for check in checks if check.get("score", 0) > 0]
    base = ""
    if not concerning:
        base = "No meaningful URL-level heuristic indicators were found."
    elif any(check.get("category") == "correlation" for check in checks):
        base = "Multiple correlated phishing indicators were detected simultaneously."
    else:
        base = concerning[0]

    if ml_prob is not None:
        ml_pct = int(round(ml_prob * 100))
        return f"{verdict}: {base} (AI/ML Classifier Risk: {ml_pct}%)."
    return f"{verdict}: {base}"


def create_analysis_result(
    url: str,
    checks: List[dict],
    ml_prob: Optional[float] = None,
    ml_details: Optional[dict] = None,
) -> dict:
    """
    Create the hybrid analysis result combining correlated heuristic rules and AI/ML model.
    """
    checks_with_escalation = apply_correlation_rules(checks)
    rule_score = calculate_score(checks_with_escalation)

    if ml_prob is not None:
        ml_score = int(round(ml_prob * 100))
        final_score = int(round(0.5 * rule_score + 0.5 * ml_score))
        final_score = min(MAX_SCORE, max(0, final_score))
    else:
        ml_score = None
        final_score = rule_score

    verdict = get_verdict(final_score, checks_with_escalation)
    summary = build_summary(verdict, checks_with_escalation, ml_prob)

    return {
        "url": url,
        "score": final_score,
        "verdict": verdict,
        "summary": summary,
        "rule_score": rule_score,
        "ml_score": ml_score,
        "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
        "ml_details": ml_details or {},
        "checks": checks_with_escalation,
    }

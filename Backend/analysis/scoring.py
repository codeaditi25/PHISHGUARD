"""Weighted, correlation-aware risk scoring for LinkShield."""

MAX_SCORE = 100
VERDICTS = ((20, "Low Risk"), (40, "Caution"), (60, "Suspicious"), (80, "High Risk"), (101, "Critical / Likely Phishing"))


def make_escalation(severity: str, score: int, reason: str) -> dict:
    return {"name": "Correlated Phishing Signals", "status": "danger" if severity in {"HIGH", "CRITICAL"} else "warning", "severity": severity, "score": score, "reason": reason, "category": "correlation"}


def apply_correlation_rules(checks: list[dict]) -> list[dict]:
    """Add explicit bonuses for combinations that are worse than their parts."""
    names = {check["name"] for check in checks if check.get("score", 0) > 0}
    bonuses: list[dict] = []

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
    # Do not double-count a specific correlation as a separate generic
    # medium-signal cluster; one explicit escalation already captures it.
    elif medium >= 3 and not bonuses:
        bonuses.append(make_escalation("HIGH", 12, "Several medium-severity phishing indicators were detected together."))
    return checks + bonuses


def calculate_score(checks: list[dict]) -> int:
    total = 0
    for check in checks:
        try:
            total += max(0, int(check.get("score", 0)))
        except (ValueError, TypeError):
            continue
    return min(total, MAX_SCORE)


def get_verdict(score: int, checks: list[dict]) -> str:
    """Apply hard severity floors so weak passes never erase dangerous signals."""
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


def build_summary(verdict: str, checks: list[dict]) -> str:
    concerning = [check["reason"] for check in checks if check.get("score", 0) > 0]
    if not concerning:
        return "No meaningful URL-level phishing indicators were found. This is not a guarantee that the destination is safe."
    if any(check["category"] == "correlation" for check in checks):
        return "Multiple phishing indicators were detected simultaneously. Their combination substantially raises the likelihood of deception."
    return f"{verdict}: " + concerning[0]


def create_analysis_result(url: str, checks: list[dict]) -> dict:
    checks_with_escalation = apply_correlation_rules(checks)
    score = calculate_score(checks_with_escalation)
    verdict = get_verdict(score, checks_with_escalation)
    return {"url": url, "score": score, "verdict": verdict, "summary": build_summary(verdict, checks_with_escalation), "checks": checks_with_escalation}

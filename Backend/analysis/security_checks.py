"""Security-first, URL-only phishing heuristics.

The checker never visits a submitted URL. It identifies structural signals and
escalates correlated deception, impersonation, and sensitive-action patterns.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from .url_parser import is_ip_address

KEYWORD_WEIGHTS = {
    "login": 5, "signin": 5, "sign-in": 5, "verify": 6, "verification": 6,
    "account": 5, "secure": 3, "security": 4, "update": 2, "password": 7,
    "wallet": 6, "bank": 7, "banking": 7, "payment": 7, "billing": 6,
    "invoice": 4, "refund": 4, "claim": 4, "reward": 3, "prize": 4,
    "free": 2, "gift": 3, "crypto": 5, "bitcoin": 5, "authentication": 7,
    "confirm": 5, "unlock": 5, "suspended": 6, "urgent": 4, "alert": 3,
    "card": 6, "otp": 8, "recovery": 7,
}
SENSITIVE_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "account",
    "password", "wallet", "bank", "banking", "payment", "billing",
    "authentication", "confirm", "unlock", "card", "otp", "recovery",
}
REDIRECT_KEYS = {"redirect", "return", "returnurl", "next", "continue", "url", "target", "dest", "destination"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"}
BRAND_DOMAINS = {
    "google": {"google.com"}, "microsoft": {"microsoft.com"}, "apple": {"apple.com"},
    "amazon": {"amazon.com"}, "paypal": {"paypal.com"}, "facebook": {"facebook.com"},
    "instagram": {"instagram.com"}, "netflix": {"netflix.com"}, "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com"}, "chatgpt": {"chatgpt.com", "openai.com"},
}


def make_result(name: str, severity: str, score: int, reason: str, category: str) -> dict:
    """Return a stable API shape; status preserves the existing UI styling."""
    status = "safe" if severity == "INFO" else "warning" if severity in {"LOW", "MEDIUM"} else "danger"
    return {"name": name, "status": status, "severity": severity, "score": score, "reason": reason, "category": category}


def _safe(name: str, reason: str, category: str) -> dict:
    return make_result(name, "INFO", 0, reason, category)


def extract_signals(parsed: dict) -> dict:
    """Decode URL text before token matching so encoded phishing paths are visible."""
    text = " ".join((parsed["hostname"], unquote_plus(parsed["path"]), unquote_plus(parsed["query"]))).lower()
    tokens = set(re.findall(r"[a-z0-9-]+", text))
    found = [word for word in KEYWORD_WEIGHTS if word in tokens]
    for word in KEYWORD_WEIGHTS:
        if word not in found and re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", text):
            found.append(word)
    sensitive = [word for word in found if word in SENSITIVE_KEYWORDS]
    redirect_keys = [key for key, _ in parsed["query_pairs"] if key.lower() in REDIRECT_KEYS]
    return {"keywords": found, "sensitive": sensitive, "redirect_keys": redirect_keys, "text": text}


def check_protocol(parsed, signals):
    if parsed["scheme"] == "https":
        return _safe("Protocol", "HTTPS encrypts the connection but is not proof of legitimacy.", "protocol")
    if parsed["scheme"] == "http":
        return make_result("Protocol", "MEDIUM", 14, "The URL uses unencrypted HTTP.", "protocol")
    return make_result("Protocol", "MEDIUM", 12, f"The URL uses the uncommon '{parsed['scheme']}' protocol.", "protocol")


def check_ip_as_domain(parsed, signals):
    if not is_ip_address(parsed["hostname"]):
        return _safe("IP Address Domain", "The hostname is a domain name rather than an IP address.", "domain")
    if signals["sensitive"]:
        return make_result("IP Address Domain", "CRITICAL", 42, "An IP address hosts a sensitive-action URL, a strong phishing pattern.", "deception")
    return make_result("IP Address Domain", "HIGH", 32, "The hostname is an IP address rather than a normal domain.", "deception")


def check_at_symbol(parsed, signals):
    if "@" not in parsed["netloc"]:
        return _safe("URL @ Symbol", "No user-info @ syntax was found in the URL.", "deception")
    return make_result("URL @ Symbol", "CRITICAL", 38, f"User-info syntax hides the real destination hostname: {parsed['hostname']}.", "deception")


def check_keywords(parsed, signals):
    found = signals["keywords"]
    if not found:
        return _safe("Suspicious Keywords", "No common credential, payment, or urgency terms were detected.", "content")
    weight = sum(KEYWORD_WEIGHTS[word] for word in found)
    if len(signals["sensitive"]) >= 2 or weight >= 16:
        return make_result("Suspicious Keywords", "HIGH", min(30, weight + 8), f"Multiple sensitive terms were found: {', '.join(found)}.", "sensitive")
    if len(found) >= 2 or signals["sensitive"]:
        return make_result("Suspicious Keywords", "MEDIUM", min(20, weight + 5), f"Sensitive or suspicious terms were found: {', '.join(found)}.", "sensitive")
    return make_result("Suspicious Keywords", "LOW", min(8, weight + 2), f"A weak indicator was found: {', '.join(found)}.", "content")


def check_sensitive_action(parsed, signals):
    count = len(signals["sensitive"])
    if count == 0:
        return _safe("Sensitive Action Pattern", "No credential, payment, or account-recovery action pattern was detected.", "sensitive")
    if count >= 3:
        return make_result("Sensitive Action Pattern", "HIGH", 28, f"The URL combines multiple sensitive actions: {', '.join(signals['sensitive'])}.", "sensitive")
    if count == 2:
        return make_result("Sensitive Action Pattern", "MEDIUM", 22, f"The URL combines sensitive actions: {', '.join(signals['sensitive'])}.", "sensitive")
    return make_result("Sensitive Action Pattern", "MEDIUM", 10, f"The URL requests a sensitive action: {signals['sensitive'][0]}.", "sensitive")


def check_subdomains(parsed, signals):
    count = parsed["subdomain_count"]
    if count >= 4:
        score = 26 if signals["sensitive"] else 18
        return make_result("Subdomain Depth", "HIGH", score, f"The hostname contains {count} subdomain levels.", "domain")
    if count >= 2:
        score = 16 if signals["sensitive"] else 9
        return make_result("Subdomain Depth", "MEDIUM", score, f"The hostname contains {count} subdomain levels.", "domain")
    return _safe("Subdomain Depth", "The hostname has a normal subdomain depth.", "domain")


def check_hyphens(parsed, signals):
    count = parsed["hostname"].count("-")
    if count >= 4:
        return make_result("Domain Hyphens", "HIGH", 16, f"The hostname contains {count} hyphens, which can obscure a deceptive domain.", "domain")
    if count >= 2:
        score = 10 if signals["sensitive"] else 7
        return make_result("Domain Hyphens", "MEDIUM", score, f"The hostname contains {count} hyphens.", "domain")
    if count == 1:
        return make_result("Domain Hyphens", "LOW", 3, "The hostname contains one hyphen; this alone is weak evidence.", "domain")
    return _safe("Domain Hyphens", "The hostname does not contain hyphen-based obfuscation.", "domain")


def check_unicode_homoglyph(parsed, signals):
    hostname = parsed["hostname"]
    if any(ord(char) > 127 for char in hostname):
        return make_result("Unicode / Homoglyph", "CRITICAL", 34, "The hostname contains Unicode characters that may visually impersonate another domain.", "impersonation")
    if "xn--" in hostname:
        return make_result("Unicode / Homoglyph", "HIGH", 26, "The hostname uses Punycode and should be checked for IDN impersonation.", "impersonation")
    return _safe("Unicode / Homoglyph", "No Unicode or Punycode hostname indicator was detected.", "impersonation")


def _distance(left: str, right: str) -> int:
    row = list(range(len(right) + 1))
    for i, char in enumerate(left, 1):
        next_row = [i]
        for j, other in enumerate(right, 1):
            next_row.append(min(next_row[-1] + 1, row[j] + 1, row[j - 1] + (char != other)))
        row = next_row
    return row[-1]


def check_brand_typosquat(parsed, signals):
    hostname, registered = parsed["hostname"], parsed["registrable_domain"]
    if any(registered == official or registered.endswith(f".{official}") for domains in BRAND_DOMAINS.values() for official in domains):
        return _safe("Brand Impersonation", "The hostname matches a known official brand domain.", "impersonation")
    label = registered.split(".")[0]
    pieces = [piece for piece in re.split(r"[-_]", label) if piece]
    translate = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})
    for brand in BRAND_DOMAINS:
        normalized_pieces = [piece.translate(translate) for piece in pieces]
        close_match = any(_distance(piece, brand) <= 1 for piece in normalized_pieces if len(piece) >= 4)
        embedded_brand = brand in normalized_pieces or brand in label
        if close_match or embedded_brand:
            if signals["sensitive"] or "-" in label:
                return make_result("Brand Impersonation", "CRITICAL", 38, f"The non-official domain resembles '{brand}' and includes deceptive context.", "impersonation")
            return make_result("Brand Impersonation", "HIGH", 22, f"The non-official domain resembles the brand '{brand}'.", "impersonation")
    return _safe("Brand Impersonation", "No obvious brand-impersonation pattern was detected.", "impersonation")


def check_shortener(parsed, signals):
    if parsed["hostname"] not in URL_SHORTENERS:
        return _safe("URL Shortener", "The URL does not use a recognized shortening service.", "redirect")
    if signals["redirect_keys"] or signals["sensitive"]:
        return make_result("URL Shortener", "MEDIUM", 18, "A URL shortener hides a redirect or sensitive destination pattern.", "redirect")
    return make_result("URL Shortener", "LOW", 9, "A URL shortener hides the final destination.", "redirect")


def check_obfuscation(parsed, signals):
    text = signals["text"]
    encoded, params = parsed["encoded_sequence_count"], len(parsed["query_pairs"])
    javascript_like = bool(re.search(r"(?:javascript:|data:|<script|eval\(|document\.cookie)", text))
    hex_runs = len(re.findall(r"(?:[a-f0-9]{16,})", text))
    if javascript_like or encoded >= 8 or hex_runs >= 2:
        return make_result("Encoding / Obfuscation", "HIGH", 22, "The URL contains heavy encoding or script-like obfuscation.", "obfuscation")
    if encoded >= 3 or params >= 6 or signals["redirect_keys"]:
        return make_result("Encoding / Obfuscation", "MEDIUM", 12, "The URL contains encoded data, many parameters, or redirect controls.", "obfuscation")
    return _safe("Encoding / Obfuscation", "No significant URL encoding or parameter obfuscation was detected.", "obfuscation")


def check_url_length(parsed, signals):
    length = len(parsed["normalized"])
    if length > 240:
        return make_result("URL Length", "MEDIUM", 14, f"The URL is unusually long ({length} characters).", "obfuscation")
    if length > 140:
        return make_result("URL Length", "LOW", 7, f"The URL is relatively long ({length} characters).", "obfuscation")
    return _safe("URL Length", "The URL length is within a normal range.", "obfuscation")


def check_random_domain(parsed, signals):
    hostname = parsed["hostname"]
    if is_ip_address(hostname):
        return _safe("Random Domain Pattern", "IP-address hosts are assessed separately.", "domain")
    label = parsed["registrable_domain"].split(".")[0]
    digits = sum(char.isdigit() for char in label)
    consonants = re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", label.lower())
    if len(label) >= 18 and (digits >= 4 or consonants):
        return make_result("Random Domain Pattern", "MEDIUM", 12, "The registrable domain looks unusually long and algorithmic.", "domain")
    if digits >= 4 or consonants:
        return make_result("Random Domain Pattern", "LOW", 6, "The domain has a weak random-looking pattern.", "domain")
    return _safe("Random Domain Pattern", "No strong random-domain indicator was detected.", "domain")


def run_security_checks(url: str, parsed: dict) -> list[dict]:
    signals = extract_signals(parsed)
    return [
        check_protocol(parsed, signals), check_ip_as_domain(parsed, signals), check_at_symbol(parsed, signals),
        check_keywords(parsed, signals), check_sensitive_action(parsed, signals), check_subdomains(parsed, signals),
        check_hyphens(parsed, signals), check_unicode_homoglyph(parsed, signals), check_brand_typosquat(parsed, signals),
        check_shortener(parsed, signals), check_obfuscation(parsed, signals), check_url_length(parsed, signals), check_random_domain(parsed, signals),
    ]

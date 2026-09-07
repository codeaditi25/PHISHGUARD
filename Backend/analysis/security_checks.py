"""
LinkShield - Security Checks

Purpose:
    Perform individual heuristic checks on a parsed URL.

Each check returns:
    name
    status
    score
    reason

The checks do not produce the final verdict.
That job belongs to scoring.py.
"""

import re

from urllib.parse import urlparse

from .url_parser import (
    is_ip_address,
)


# =========================================================
# CONFIGURATION
# =========================================================

# Words frequently found in suspicious/phishing URLs.
#
# IMPORTANT:
# These words are indicators only.
# A legitimate website may also contain them.
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "confirmation",
    "password",
    "signin",
    "sign-in",
    "banking",
    "wallet",
    "payment",
    "invoice",
    "credential",
    "recover",
    "unlock",
}

# Common legitimate URL-shortening services.
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}


# =========================================================
# HELPER FUNCTION
# =========================================================

def make_result(name, status, score, reason):
    """
    Create a standard result object.

    Keeping the same structure for every check makes it
    easier for scoring.py and results.js to process them.
    """

    return {
        "name": name,
        "status": status,
        "score": score,
        "reason": reason,
    }


# =========================================================
# CHECK 1: URL LENGTH
# =========================================================

def check_url_length(url: str):
    """
    Very long URLs can sometimes be used to hide suspicious
    destinations or overwhelm users.

    A long URL is NOT automatically malicious.
    """

    length = len(url)

    if length > 200:
        return make_result(
            "URL Length",
            "danger",
            10,
            f"The URL is unusually long ({length} characters)."
        )

    if length > 100:
        return make_result(
            "URL Length",
            "warning",
            5,
            f"The URL is relatively long ({length} characters)."
        )

    return make_result(
        "URL Length",
        "safe",
        0,
        "The URL length is within a normal range."
    )


# =========================================================
# CHECK 2: HTTPS
# =========================================================

def check_https(parsed: dict):
    """
    Check whether the URL uses HTTPS.

    HTTPS is good, but HTTPS alone does NOT prove that
    a website is legitimate.
    """

    scheme = parsed["scheme"]

    if scheme == "https":
        return make_result(
            "HTTPS",
            "safe",
            0,
            "The website uses HTTPS."
        )

    return make_result(
        "HTTPS",
        "warning",
        5,
        "The URL does not use HTTPS."
    )


# =========================================================
# CHECK 3: IP AS DOMAIN
# =========================================================

def check_ip_as_domain(parsed: dict):
    """
    Detect URLs that use an IP address instead of a
    normal domain name.

    Example:
        http://192.168.1.10/login
    """

    hostname = parsed["hostname"]

    if is_ip_address(hostname):
        return make_result(
            "IP Address Domain",
            "danger",
            20,
            "The hostname is an IP address instead of a normal domain."
        )

    return make_result(
        "IP Address Domain",
        "safe",
        0,
        "The hostname is a normal domain name."
    )


# =========================================================
# CHECK 4: SUSPICIOUS KEYWORDS
# =========================================================

def check_suspicious_keywords(parsed: dict):
    """
    Search the hostname and path for words frequently
    associated with phishing attempts.
    """

    text = (
        parsed["hostname"] +
        " " +
        parsed["path"] +
        " " +
        parsed["query"]
    ).lower()

    found = [
        word
        for word in SUSPICIOUS_KEYWORDS
        if word in text
    ]

    # Remove duplicates while keeping order.
    found = list(dict.fromkeys(found))

    if len(found) >= 3:
        return make_result(
            "Suspicious Keywords",
            "danger",
            15,
            "Multiple suspicious keywords were found: "
            + ", ".join(found)
        )

    if found:
        return make_result(
            "Suspicious Keywords",
            "warning",
            7,
            "Potentially sensitive keywords were found: "
            + ", ".join(found)
        )

    return make_result(
        "Suspicious Keywords",
        "safe",
        0,
        "No suspicious keywords were detected."
    )


# =========================================================
# CHECK 5: SUBDOMAIN COUNT
# =========================================================

def check_subdomains(parsed: dict):
    """
    Too many subdomain levels can sometimes be used to
    make a malicious domain appear more trustworthy.

    Example:

        login.security.account.example.com
    """

    count = parsed["subdomain_count"]

    if count >= 4:
        return make_result(
            "Subdomain Count",
            "danger",
            12,
            f"The URL contains {count} subdomain levels."
        )

    if count >= 2:
        return make_result(
            "Subdomain Count",
            "warning",
            5,
            f"The URL contains {count} subdomain levels."
        )

    return make_result(
        "Subdomain Count",
        "safe",
        0,
        "The URL has a normal number of subdomain levels."
    )


# =========================================================
# CHECK 6: @ SYMBOL
# =========================================================

def check_at_symbol(parsed: dict):
    """
    Detect the @ symbol in the URL.

    URLs can use:

        https://trusted-site.com@evil-site.com

    The actual hostname is evil-site.com.

    This technique can confuse users who only look at the
    beginning of the URL.
    """

    netloc = parsed["netloc"]

    if "@" in netloc:
        return make_result(
            "URL @ Symbol",
            "danger",
            20,
            "The URL contains an @ symbol that may hide the actual destination."
        )

    return make_result(
        "URL @ Symbol",
        "safe",
        0,
        "No suspicious @ symbol was found in the URL."
    )


# =========================================================
# CHECK 7: HYPHEN COUNT
# =========================================================

def check_hyphens(parsed: dict):
    """
    Excessive hyphens in a domain can sometimes indicate
    a generated or deceptive domain.

    A small number of hyphens is common in legitimate domains.
    """

    hostname = parsed["hostname"]

    count = hostname.count("-")

    if count >= 4:
        return make_result(
            "Domain Hyphens",
            "danger",
            10,
            f"The domain contains {count} hyphens."
        )

    if count >= 2:
        return make_result(
            "Domain Hyphens",
            "warning",
            4,
            f"The domain contains {count} hyphens."
        )

    return make_result(
        "Domain Hyphens",
        "safe",
        0,
        "The domain does not contain an unusual number of hyphens."
    )


# =========================================================
# CHECK 8: UNICODE / HOMOGLYPH
# =========================================================

def check_unicode_homoglyph(parsed: dict):
    """
    Detect non-ASCII characters in the hostname.

    Unicode can be used in IDN homograph attacks where a
    character visually resembles another character.

    Example conceptually:

        a legitimate-looking Latin character
        vs.
        a visually similar Unicode character
    """

    hostname = parsed["hostname"]

    if any(ord(char) > 127 for char in hostname):

        return make_result(
            "Unicode / Homoglyph",
            "danger",
            15,
            "The hostname contains non-ASCII characters that may be used for visual impersonation."
        )

    # Punycode domains begin with xn--.
    if "xn--" in hostname:

        return make_result(
            "Unicode / Homoglyph",
            "warning",
            8,
            "The hostname contains Punycode and should be checked carefully."
        )

    return make_result(
        "Unicode / Homoglyph",
        "safe",
        0,
        "No obvious Unicode or Punycode indicator was detected."
    )


# =========================================================
# CHECK 9: BRAND / TYPOSQUATTING
# =========================================================

def check_brand_typosquat(parsed: dict):
    """
    Detect obvious brand-name patterns in a domain.

    This is intentionally conservative.

    It does NOT claim that a domain is fake just because
    it contains a brand name.
    """

    hostname = parsed["hostname"]

    # Common brands for demonstration.
    # This list can later move into config.py or a database.
    brands = {
        "google",
        "microsoft",
        "apple",
        "amazon",
        "paypal",
        "facebook",
        "instagram",
        "netflix",
        "linkedin",
        "whatsapp",
        "chatgpt",
    }

    for brand in brands:

        # Brand name appears in hostname.
        if brand in hostname:

            # Remove the brand to inspect surrounding text.
            remaining = hostname.replace(brand, "")

            # Suspicious indicators around the brand.
            suspicious_parts = [
                "-",
                "login",
                "secure",
                "verify",
                "account",
                "support",
                "official",
            ]

            if any(part in remaining for part in suspicious_parts):

                return make_result(
                    "Brand Typosquatting",
                    "danger",
                    18,
                    f"The domain contains the brand name '{brand}' with additional suspicious domain text."
                )

    return make_result(
        "Brand Typosquatting",
        "safe",
        0,
        "No obvious brand-impersonation pattern was detected."
    )


# =========================================================
# CHECK 10: URL SHORTENER
# =========================================================

def check_shortener(parsed: dict):
    """
    Detect common URL-shortening services.

    Shorteners are legitimate, so this is only a warning,
    not proof of phishing.
    """

    hostname = parsed["hostname"]

    if hostname in URL_SHORTENERS:
        return make_result(
            "URL Shortener",
            "warning",
            8,
            "The URL uses a shortening service, which hides the final destination."
        )

    return make_result(
        "URL Shortener",
        "safe",
        0,
        "The URL does not use a recognized shortening service."
    )


# =========================================================
# CHECK 11: RANDOM-LOOKING DOMAIN
# =========================================================

def check_random_domain(parsed: dict):
    """
    Look for domains that have characteristics of randomly
    generated names.

    This is intentionally a weak heuristic because many
    legitimate services use generated domains.
    """

    hostname = parsed["hostname"]

    # Remove common TLD.
    domain_parts = hostname.split(".")

    if len(domain_parts) < 2:
        return make_result(
            "Random Domain Pattern",
            "safe",
            0,
            "The domain structure could not be considered suspicious."
        )

    domain_name = domain_parts[-2]

    # A long domain with many digits can be suspicious.
    digit_count = sum(char.isdigit() for char in domain_name)

    # Count consonant runs as a simple indicator of random-looking text.
    consonant_runs = re.findall(
        r"[bcdfghjklmnpqrstvwxyz]{5,}",
        domain_name.lower()
    )

    if len(domain_name) >= 15 and digit_count >= 4:

        return make_result(
            "Random Domain Pattern",
            "warning",
            7,
            "The domain contains an unusually long name with many digits."
        )

    if consonant_runs:

        return make_result(
            "Random Domain Pattern",
            "warning",
            5,
            "The domain contains patterns that may resemble a generated name."
        )

    return make_result(
        "Random Domain Pattern",
        "safe",
        0,
        "No strong random-domain indicator was detected."
    )


# =========================================================
# RUN ALL SECURITY CHECKS
# =========================================================

def run_security_checks(url: str, parsed: dict):
    """
    Execute every LinkShield heuristic.

    The returned list is passed to scoring.py.
    """

    return [
        check_url_length(url),
        check_https(parsed),
        check_ip_as_domain(parsed),
        check_suspicious_keywords(parsed),
        check_subdomains(parsed),
        check_at_symbol(parsed),
        check_hyphens(parsed),
        check_unicode_homoglyph(parsed),
        check_brand_typosquat(parsed),
        check_shortener(parsed),
        check_random_domain(parsed),
    ]
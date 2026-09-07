"""
LinkShield - URL Parser

Purpose:
    Parse a submitted URL into useful components.

This module does NOT decide whether a URL is malicious.
It only extracts and normalizes information that the
security-checking module can use.
"""

from urllib.parse import urlparse
import ipaddress


def normalize_url(url: str) -> str:
    """
    Normalize the URL before analysis.

    If the user enters:
        google.com

    we internally treat it as:
        https://google.com

    This does NOT mean we are visiting the website.
    """

    url = url.strip()

    if not url:
        return ""

    # Add HTTPS only when the user did not provide a scheme.
    if not urlparse(url).scheme:
        url = "https://" + url

    return url


def parse_url(url: str) -> dict:
    """
    Parse a URL and return its important components.

    Returns:
        A dictionary containing scheme, hostname, port,
        path, query, fragment, etc.
    """

    normalized = normalize_url(url)

    parsed = urlparse(normalized)

    hostname = parsed.hostname or ""

    return {
        "original": url,
        "normalized": normalized,

        # Example: https
        "scheme": parsed.scheme.lower(),

        # Example: example.com
        "hostname": hostname.lower(),

        # Example: 443
        "port": parsed.port,

        # Example: /login/account
        "path": parsed.path,

        # Example: user=123
        "query": parsed.query,

        # Example: section
        "fragment": parsed.fragment,

        # Username/password can be useful when detecting
        # suspicious URL structures.
        "username": parsed.username,

        "password": parsed.password,

        # Complete network location.
        "netloc": parsed.netloc,

        # Number of subdomains.
        "subdomain_count": count_subdomains(hostname),

        # Whether hostname is an IP address.
        "is_ip": is_ip_address(hostname),
    }


def is_ip_address(hostname: str) -> bool:
    """
    Determine whether the hostname is an IPv4 or IPv6 address.

    Example:

        192.168.1.1
        2001:db8::1

    return True.

    Example:

        google.com

    return False.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def count_subdomains(hostname: str) -> int:
    """
    Count subdomain levels.

    Example:

        login.example.com

    returns:
        1

    Example:

        secure.login.example.com

    returns:
        2

    The main domain is not counted as a subdomain.
    """

    if not hostname or is_ip_address(hostname):
        return 0

    parts = hostname.split(".")

    # A normal domain such as example.com has two parts.
    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def get_url_length(url: str) -> int:
    """
    Return the total URL length.
    """

    return len(url)


def get_domain_length(hostname: str) -> int:
    """
    Return the hostname/domain length.
    """

    return len(hostname)


def get_path_length(path: str) -> int:
    """
    Return the URL path length.
    """

    return len(path)
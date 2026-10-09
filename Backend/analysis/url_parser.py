"""Safe URL normalization and signal extraction for LinkShield."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, unquote_plus, urlparse

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "com.br", "co.jp", "co.nz", "com.mx",
}


def normalize_url(url: str) -> str:
    """Trim a user value and add HTTPS only when it has no scheme."""
    url = url.strip()
    if not url:
        return ""
    return url if urlparse(url).scheme else f"https://{url}"


def is_ip_address(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def get_registrable_domain(hostname: str) -> str:
    """Return a best-effort registrable domain without treating IPs as names."""
    if not hostname or is_ip_address(hostname):
        return hostname
    labels = hostname.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    suffix_size = 2 if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 1
    return ".".join(labels[-(suffix_size + 1):])


def count_subdomains(hostname: str) -> int:
    if not hostname or is_ip_address(hostname):
        return 0
    labels = hostname.lower().strip(".").split(".")
    registered = get_registrable_domain(hostname).split(".")
    return max(0, len(labels) - len(registered))


def parse_url(url: str) -> dict:
    """Parse once and expose decoded fields used by the security checks."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    decoded_path = unquote_plus(parsed.path)
    decoded_query = unquote_plus(parsed.query)

    return {
        "original": url,
        "normalized": normalized,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        # Raises ValueError for a malformed port; the API turns it into HTTP 400.
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "decoded_path": decoded_path,
        "decoded_query": decoded_query,
        "query_pairs": parse_qsl(parsed.query, keep_blank_values=True),
        "fragment": parsed.fragment,
        "username": parsed.username,
        "password": parsed.password,
        "netloc": parsed.netloc,
        "subdomain_count": count_subdomains(hostname),
        "registrable_domain": get_registrable_domain(hostname),
        "is_ip": is_ip_address(hostname),
        "encoded_sequence_count": len(re.findall(r"%[0-9a-fA-F]{2}", normalized)),
    }

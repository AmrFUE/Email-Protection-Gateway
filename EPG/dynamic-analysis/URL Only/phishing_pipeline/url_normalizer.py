"""
url_normalizer.py — Step 2: Normalize extracted URLs.

Normalization steps:
  1. URL-decode percent-encoded characters
  2. Lowercase scheme and host
  3. Remove tracking / junk query parameters
  4. Strip URL fragment (#…)
  5. Collapse duplicate slashes in the path
  6. Reconstruct with urllib.parse.urlunparse
"""

import re
from urllib.parse import (
    urlparse, urlunparse, unquote, urlencode, parse_qsl,
)
from .config import JUNK_PARAM_PREFIXES
from .logger import get_logger

log = get_logger("url_normalizer")

# Matches runs of two or more forward slashes NOT at the start of the path
_DOUBLE_SLASH: re.Pattern = re.compile(r"(?<!:)//+")


def _strip_junk_params(query: str) -> str:
    """
    Remove known tracking / junk query parameters from a query string.
    Keeps parameters whose names do not match any junk prefix.
    """
    params = parse_qsl(query, keep_blank_values=True)
    kept = [
        (k, v)
        for k, v in params
        if not any(k.lower().startswith(p) for p in JUNK_PARAM_PREFIXES)
    ]
    return urlencode(kept)


def normalize_url(url: str) -> str:
    """
    Normalize a URL through decoding, lowercasing, junk-param removal,
    fragment stripping, and path canonicalization.

    Args:
        url: Raw URL string.

    Returns:
        Cleaned, normalized URL string. Returns the original url on error.
    """
    try:
        # Step 1 — percent-decode
        url = unquote(url)

        parsed = urlparse(url)

        # Step 2 — lowercase scheme + host
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Step 3 — strip junk query params
        clean_query = _strip_junk_params(parsed.query)

        # Step 4 — drop fragment
        fragment = ""

        # Step 5 — collapse duplicate slashes in path
        path = _DOUBLE_SLASH.sub("/", parsed.path)

        normalized = urlunparse((scheme, netloc, path, parsed.params, clean_query, fragment))
        log.debug("Normalized: %s  →  %s", url, normalized)
        return normalized

    except Exception as exc:
        log.warning("normalize_url failed for '%s': %s", url, exc)
        return url

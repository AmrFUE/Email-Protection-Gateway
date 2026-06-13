"""
defacement_detector.py — DOM-level web defacement detection.

Defacement is a class of attack where a hacker replaces the legitimate
content of a webpage with their own message (graffiti, propaganda, ransom).

Unlike phishing, defacement does NOT collect credentials — so VirusTotal
often does NOT flag defaced pages as "malicious". A separate DOM-level
scan is required.

This module inspects:
  1. Page title patterns (e.g. "Hacked by", "0wned")
  2. Page body keywords from known defacement groups / messages
  3. Low legitimate content + presence of attacker fingerprints
  4. Structural anomalies (very short body, all images gone, etc.)
"""

from __future__ import annotations

import re
from bs4 import BeautifulSoup
from .logger import get_logger

log = get_logger("defacement_detector")


# ── Defacement signature patterns ─────────────────────────────────────────────
# These are the most common phrases left by web defacers.
# Sources: mirror-h.org, zone-h.org, defacement databases.

_DEFACEMENT_TITLE_RE = re.compile(
    r"\b("
    r"hacked?\s+by|h4ck3d|0wned\s+by|owned\s+by|"
    r"pwned\s+by|defaced?\s+by|rooted\s+by|"
    r"was\s+here|r00t|cr3w|team|group|cyber\s+attack|"
    r"security\s+fail|under\s+attack|site\s+hacked"
    r")\b",
    re.IGNORECASE,
)

_DEFACEMENT_BODY_RE = re.compile(
    r"\b("
    # Classic defacement phrases
    r"hacked\s+by|hacked!|0wn3d|h4x0r|"
    r"owned\s+by|pwned\s+by|defaced\s+by|rooted\s+by|"
    r"cracked\s+by|coded\s+by\s+\w|"
    # Common defacement group signatures
    r"ghost\s+squad|anonymous\s+hackers?|lulzsec|"
    r"team\s+poison|dark\s+c0de|the\s+hackers?|"
    r"black\s+hat|whitehat\s+error|mr\.\s*robot|"
    r"greetz\s+to|greet\s+to\s+all|shout\s+out\s+to|"
    # Typical defacement messages
    r"your\s+security\s+sucks|fix\s+your\s+security|"
    r"no\s+system\s+is\s+safe|feel\s+the\s+power\s+of|"
    r"this\s+site\s+has\s+been\s+compromised|"
    r"this\s+page\s+has\s+been\s+defaced|"
    r"this\s+server\s+has\s+been\s+hacked|"
    r"i\s+am\s+in\s+your\s+system|"
    # Middle-Eastern / hacktivist groups
    r"gaza\s+hacker\s+team|team\s+evil|dr\.?\s+s4tan|"
    r"system\s+failure\s+by"
    r")\b",
    re.IGNORECASE,
)

# Short page: if text under N chars and has defacement signal → strong indicator
_DEFACEMENT_SHORT_THRESHOLD = 500  # characters of visible text

# Structural defacement: typically the original menus, styles are wiped
# and replaced with a single full-screen block
_DEFACEMENT_VISUAL_MARKERS = [
    "you have been hacked",
    "this website has been hacked",
    "this site has been hacked",
    "this page has been hacked",
    "site defaced",
    "server hacked",
    "system compromised",
]


def detect_defacement(html: str) -> dict:
    """
    Scan page HTML for defacement signatures.

    Args:
        html: Full HTML content of the page (from page.content() or requests).

    Returns:
        Dict with keys:
            web_defacement_detected   — 1 if defacement is likely, 0 otherwise
            web_defacement_confidence — 'high' / 'medium' / 'low' / 'none'
            web_defacement_reason     — human-readable description of finding
    """
    result = {
        "web_defacement_detected": 0,
        "web_defacement_confidence": "none",
        "web_defacement_reason": "",
    }

    if not html:
        return result

    try:
        soup = BeautifulSoup(html, "html.parser")

        # Extract title
        title_tag = soup.find("title")
        title_text = title_tag.get_text(strip=True) if title_tag else ""

        # Extract visible body text (strip scripts/styles)
        for tag in soup(["script", "style", "noscript", "meta", "head"]):
            tag.decompose()
        body_text = soup.get_text(" ", strip=True)

        # ── Check 1: Title contains defacement phrase ─────────────────────────
        if title_text and _DEFACEMENT_TITLE_RE.search(title_text):
            result["web_defacement_detected"] = 1
            result["web_defacement_confidence"] = "high"
            result["web_defacement_reason"] = (
                f"Page title contains defacement signature: '{title_text[:120]}'"
            )
            log.warning("Defacement detected via title: %s", title_text[:80])
            return result

        # ── Check 2: Body contains known defacement phrases ───────────────────
        body_match = _DEFACEMENT_BODY_RE.search(body_text)
        if body_match:
            snippet = body_text[max(0, body_match.start()-30): body_match.end()+30]
            confidence = (
                "high" if len(body_text) < _DEFACEMENT_SHORT_THRESHOLD
                else "medium"
            )
            result["web_defacement_detected"] = 1
            result["web_defacement_confidence"] = confidence
            result["web_defacement_reason"] = (
                f"Defacement keyword found in page body: '…{snippet.strip()[:120]}…'"
            )
            log.warning("Defacement keyword found: %s", snippet.strip()[:80])
            return result

        # ── Check 3: Exact known defacement sentences ─────────────────────────
        body_lower = body_text.lower()
        for marker in _DEFACEMENT_VISUAL_MARKERS:
            if marker in body_lower:
                result["web_defacement_detected"] = 1
                result["web_defacement_confidence"] = "high"
                result["web_defacement_reason"] = (
                    f"Known defacement sentence found in page: '{marker}'"
                )
                log.warning("Defacement marker found: %s", marker)
                return result

        # ── Check 4: Structural anomaly — very short page with suspicious title ─
        if len(body_text) < _DEFACEMENT_SHORT_THRESHOLD and title_text:
            title_lower = title_text.lower()
            suspicious_title_words = [
                "hacked", "0wned", "owned", "defaced", "pwned",
                "r00t", "hack", "security", "crew", "team", "anonymous",
            ]
            if any(w in title_lower for w in suspicious_title_words):
                result["web_defacement_detected"] = 1
                result["web_defacement_confidence"] = "medium"
                result["web_defacement_reason"] = (
                    f"Short page body ({len(body_text)} chars) with suspicious "
                    f"title '{title_text[:80]}' — likely defaced."
                )
                log.warning("Possible defacement (short page + title): %s", title_text)
                return result

    except Exception as exc:
        log.warning("detect_defacement error: %s", exc)

    return result

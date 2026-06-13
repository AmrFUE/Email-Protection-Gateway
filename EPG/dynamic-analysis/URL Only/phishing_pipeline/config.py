"""
config.py — Central configuration for the Phishing URL Analysis Pipeline.
All API keys, constants, and shared lists live here.
"""

import os

# ──────────────────────────────────────────────────────────
# VirusTotal API Key
# Priority: environment variable → hardcoded constant below
# ──────────────────────────────────────────────────────────
VT_API_KEY: str = os.environ.get(
    "VT_API_KEY",
    "8a1568ab7ad3337d4ba1b0e3adf4c71313613a7092c28777ac8c2f91b5753a02",
)

# ──────────────────────────────────────────────────────────
# HTTP Request Settings
# ──────────────────────────────────────────────────────────
REQUEST_TIMEOUT: int = 10        # seconds for general requests
VT_POLL_WAIT: int = 15           # seconds to wait for VT scan to complete

# ──────────────────────────────────────────────────────────
# Playwright headless browser settings
# ──────────────────────────────────────────────────────────
PLAYWRIGHT_TIMEOUT: int = 20_000  # ms — page navigation timeout

# ──────────────────────────────────────────────────────────
# Screenshots directory (Step 7 — dynamic analysis)
# ──────────────────────────────────────────────────────────
import pathlib as _pathlib
SCREENSHOTS_DIR: _pathlib.Path = _pathlib.Path("screenshots")
SCREENSHOTS_DIR.mkdir(exist_ok=True)

# ──────────────────────────────────────────────────────────
# File download extension list (Step 10)
# ──────────────────────────────────────────────────────────
DOWNLOAD_EXTENSIONS: list[str] = [
    ".exe", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".msi", ".apk", ".deb", ".dmg", ".pkg",
    ".scr", ".bat", ".cmd", ".vbs", ".ps1",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".js",
]

# ──────────────────────────────────────────────────────────
# Suspicious Free / Abused TLDs (Step 4)
# ──────────────────────────────────────────────────────────
SUSPICIOUS_TLDS: set[str] = {
    # Free / abused gTLDs
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "pw", "cc",
    "buzz", "click", "link", "work", "rest",
    "loan", "win", "racing", "stream", "review",
    # Commonly abused info / biz TLDs
    "info", "biz", "mobi", "name",
    # Country codes historically abused for spam/malware
    "su",    # Soviet Union — no content policy enforcement
    "ru",    # Used in many spam campaigns  (note: many legit RU sites too)
    # New gTLDs abused for phishing/defacement
    "gdn", "men", "date", "faith", "trade", "webcam",
    "accountant", "science", "download", "party",
}

# ──────────────────────────────────────────────────────────
# Known URL shortener domains (Step 5)
# ──────────────────────────────────────────────────────────
SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link",
    "rb.gy", "shorturl.at", "cutt.ly", "tiny.cc",
    "lnkd.in", "youtu.be", "amzn.to",
}

# ──────────────────────────────────────────────────────────
# Query parameters to strip during normalization (Step 2)
# ──────────────────────────────────────────────────────────
JUNK_PARAM_PREFIXES: tuple[str, ...] = (
    "utm_", "fbclid", "gclid", "msclkid",
    "tracking", "sessionid", "sid", "ref",
    "affiliate", "campaign",
)

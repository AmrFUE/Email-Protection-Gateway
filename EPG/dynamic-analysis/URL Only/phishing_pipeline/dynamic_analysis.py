"""
dynamic_analysis.py — Steps 7–10: Headless browser analysis with Playwright.

Additions in this version:
  ✦ Screenshot capture — saves a full-page PNG to screenshots/ folder
  ✦ Defacement detection — calls defacement_detector on page HTML

Stages covered:
    Step 7  — Dynamic page loading, SSL check, HTTP status, live check
    Step 8  — DOM & form analysis (BeautifulSoup over page HTML)
    Step 8b — Defacement detection (DOM content scanner)
    Step 9  — Network request interception (external domain tracking)
    Step 10 — Download link detection in page HTML
    Screenshot — saved as PNG to screenshots/<sanitized_host>_<timestamp>.png
"""

from __future__ import annotations

import re
import hashlib
import datetime
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .config import DOWNLOAD_EXTENSIONS, PLAYWRIGHT_TIMEOUT, SCREENSHOTS_DIR
from .defacement_detector import detect_defacement
from .logger import get_logger

log = get_logger("dynamic_analysis")

# ── Regex helpers ─────────────────────────────────────────────────────────────
_DOWNLOAD_RE = re.compile(
    "|".join(re.escape(ext) for ext in DOWNLOAD_EXTENSIONS),
    re.IGNORECASE,
)

# Words that suggest a login form even without a password field
_LOGIN_WORDS_RE = re.compile(
    r"\b(login|log in|sign in|signin|username|email address)\b",
    re.IGNORECASE,
)

# Default safe result returned when the browser cannot load the page
_DEFAULT = {
    "web_http_status":          0,
    "web_is_live":              0,
    "web_ssl_valid":            0,
    "web_forms_count":          0,
    "web_password_fields":      0,
    "web_hidden_inputs":        0,
    "web_has_login":            0,
    "web_unique_domains":       0,
    "web_ext_ratio":            0.0,
    "file_download_detected":   0,
    # Defacement
    "web_defacement_detected":  0,
    "web_defacement_confidence":"none",
    "web_defacement_reason":    "",
    # Screenshot
    "web_screenshot_path":      "",
}


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_base_domain(url: str) -> str:
    """Return the netloc (host:port) of a URL, lowercased."""
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _screenshot_path(url: str) -> str:
    """
    Build a safe filesystem path for a screenshot PNG.
    Pattern: screenshots/<host>_<url_hash8>_<timestamp>.png
    """
    host = _get_base_domain(url) or "unknown"
    # Sanitize host for use as filename
    host_safe = re.sub(r"[^A-Za-z0-9.\-]", "_", host)[:40]
    url_hash = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{host_safe}_{url_hash}_{ts}.png"
    return str(SCREENSHOTS_DIR / filename)


def _analyze_dom(html: str, page_url: str) -> dict:
    """
    Parse the page HTML with BeautifulSoup and extract DOM features.
    """
    result = {
        "web_forms_count":      0,
        "web_password_fields":  0,
        "web_hidden_inputs":    0,
        "web_has_login":        0,
        "file_download_detected": 0,
    }

    try:
        soup = BeautifulSoup(html, "html.parser")

        # ── Form analysis ─────────────────────────────────────────────────────
        forms = soup.find_all("form")
        result["web_forms_count"] = len(forms)

        password_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})
        result["web_password_fields"] = len(password_inputs)

        hidden_inputs = soup.find_all("input", {"type": re.compile(r"^hidden$", re.I)})
        result["web_hidden_inputs"] = len(hidden_inputs)

        # Login indicator: password field OR login-related text on page
        page_text = soup.get_text(" ", strip=True)
        has_password = len(password_inputs) > 0
        has_login_text = bool(_LOGIN_WORDS_RE.search(page_text))
        result["web_has_login"] = 1 if (has_password or has_login_text) else 0

        # ── Download link detection ───────────────────────────────────────────
        for tag in soup.find_all(["a", "script", "iframe", "embed", "object"]):
            attr_val = tag.get("href") or tag.get("src") or tag.get("data") or ""
            if _DOWNLOAD_RE.search(attr_val):
                result["file_download_detected"] = 1
                log.debug("Download link found: %s", attr_val)
                break

    except Exception as exc:
        log.warning("_analyze_dom error: %s", exc)

    return result


def _analyze_network(requests_made: list[str], base_domain: str) -> dict:
    """
    Compute external-domain metrics from intercepted network requests.
    """
    if not requests_made:
        return {"web_unique_domains": 0, "web_ext_ratio": 0.0}

    external_domains: list[str] = []
    for req_url in requests_made:
        domain = _get_base_domain(req_url)
        if domain and domain != base_domain:
            external_domains.append(domain)

    unique_ext = len(set(external_domains))
    ext_ratio = round(len(external_domains) / len(requests_made), 4)

    return {
        "web_unique_domains": unique_ext,
        "web_ext_ratio": ext_ratio,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_dynamic(url: str) -> dict:
    """
    Load the URL in a headless Chromium browser and extract all dynamic
    features: DOM structure, defacement signals, network behaviour,
    download detection, and a full-page screenshot.

    Args:
        url: URL to analyse (normalized URL recommended).

    Returns:
        Dict with all dynamic analysis features.
        Falls back to all-zero defaults on any error.
    """
    result = dict(_DEFAULT)

    # Lazy Playwright import — graceful degradation if not installed
    try:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError
    except ImportError:
        log.error(
            "Playwright is not installed. "
            "Run: pip install playwright && playwright install chromium"
        )
        return result

    base_domain = _get_base_domain(url)
    intercepted_requests: list[str] = []
    screenshot_dest = _screenshot_path(url)

    try:
        with sync_playwright() as pw:

            # ── Launch headless Chromium ──────────────────────────────────────
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--ignore-certificate-errors",
                ],
            )

            # Isolated browser context with realistic user-agent
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                # Give the browser a realistic viewport so screenshots look normal
                viewport={"width": 1280, "height": 800},
            )

            page = context.new_page()

            # ── Network interception (Step 9) — register BEFORE navigating ────
            def _on_request(request):
                try:
                    intercepted_requests.append(request.url)
                except Exception:
                    pass

            page.on("request", _on_request)

            # ── Navigate and capture HTTP status (Step 7) ─────────────────────
            http_status = 0
            ssl_valid = 0
            is_live = 0

            try:
                response = page.goto(
                    url,
                    timeout=PLAYWRIGHT_TIMEOUT,
                    wait_until="domcontentloaded",
                )

                if response:
                    http_status = response.status
                    is_live = 1 if 200 <= http_status < 400 else 0

                    # SSL check: only meaningful for HTTPS URLs
                    if url.lower().startswith("https://"):
                        try:
                            sec = response.security_details()
                            ssl_valid = 1 if sec else 0
                        except Exception:
                            ssl_valid = 0

                log.info(
                    "Page loaded: status=%d  ssl=%d  live=%d",
                    http_status, ssl_valid, is_live,
                )

            except PlaywrightError as nav_err:
                log.warning("Navigation error for '%s': %s", url, nav_err)
                is_live = 0

            # ── Wait for JS to settle (2s) ──────────────────────────────────
            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass

            # ── Screenshot (BEFORE closing page) ─────────────────────────────
            screenshot_saved = ""
            try:
                page.screenshot(
                    path=screenshot_dest,
                    full_page=True,         # capture entire scrollable page
                    timeout=10_000,         # 10 s max
                )
                screenshot_saved = screenshot_dest
                log.info("Screenshot saved: %s", screenshot_saved)
            except Exception as sc_err:
                log.warning("Screenshot failed: %s", sc_err)

            # ── DOM analysis (Step 8) ─────────────────────────────────────────
            html_content = ""
            try:
                html_content = page.content()
                dom_features = _analyze_dom(html_content, url)
            except Exception as dom_err:
                log.warning("DOM extraction failed: %s", dom_err)
                dom_features = {}

            # ── Defacement detection (Step 8b) ────────────────────────────────
            defacement_features = {}
            try:
                defacement_features = detect_defacement(html_content)
            except Exception as def_err:
                log.warning("Defacement detection failed: %s", def_err)

            # ── Clean up browser ──────────────────────────────────────────────
            try:
                context.close()
                browser.close()
            except Exception:
                pass

            # ── Network analysis (Step 9) ─────────────────────────────────────
            net_features = _analyze_network(intercepted_requests, base_domain)

            # ── Assemble result ───────────────────────────────────────────────
            result.update({
                "web_http_status":    http_status,
                "web_is_live":        is_live,
                "web_ssl_valid":      ssl_valid,
                "web_screenshot_path": screenshot_saved,
            })
            result.update(dom_features)
            result.update(defacement_features)
            result.update(net_features)

            log.info("Dynamic analysis complete for '%s'.", url)

    except Exception as exc:
        log.error("analyze_dynamic unexpected error for '%s': %s", url, exc)

    return result

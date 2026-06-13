"""
reputation.py — Step 3: VirusTotal URL reputation check.

Flow:
  1. Submit the URL to VT's analysis endpoint (POST /urls)
  2. Wait VT_POLL_WAIT seconds for the scan to run
  3. Fetch the analysis result (GET /analyses/{id})
  4. Return counts of malicious / suspicious / harmless / undetected engines

If the API key is missing or requests fail, returns all-zero defaults
so the pipeline can continue gracefully.
"""

import base64
import time

import requests

from .config import VT_API_KEY, REQUEST_TIMEOUT, VT_POLL_WAIT
from .logger import get_logger

log = get_logger("reputation")

_VT_BASE = "https://www.virustotal.com/api/v3"
_DEFAULT_RESULT = {
    "vt_malicious": 0,
    "vt_suspicious": 0,
    "vt_harmless": 0,
    "vt_undetected": 0,
}


def _url_id(url: str) -> str:
    """
    VirusTotal v3 identifies URLs by their URL-safe base64 encoding
    (without '=' padding).
    """
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check_virustotal(url: str) -> dict:
    """
    Query VirusTotal for the given URL and return engine vote counts.

    Args:
        url: The URL to analyse (should be the normalized URL).

    Returns:
        Dict with keys: vt_malicious, vt_suspicious, vt_harmless, vt_undetected.
    """
    if not VT_API_KEY or VT_API_KEY.startswith("YOUR_"):
        log.warning("No valid VT API key — skipping reputation check.")
        return dict(_DEFAULT_RESULT)

    headers = {"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}

    # ── Step 1: Submit URL for analysis ───────────────────────────────────────
    try:
        submit_resp = requests.post(
            f"{_VT_BASE}/urls",
            headers=headers,
            data=f"url={requests.utils.quote(url, safe='')}",
            timeout=REQUEST_TIMEOUT,
        )
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json()["data"]["id"]
        log.info("VT analysis submitted — id: %s", analysis_id)
    except Exception as exc:
        log.warning("VT submission failed for '%s': %s", url, exc)
        return dict(_DEFAULT_RESULT)

    # ── Step 2: Wait for VT to finish scanning ─────────────────────────────────
    log.info("Waiting %ds for VT scan to complete…", VT_POLL_WAIT)
    time.sleep(VT_POLL_WAIT)

    # ── Step 3: Fetch analysis result ──────────────────────────────────────────
    try:
        result_resp = requests.get(
            f"{_VT_BASE}/analyses/{analysis_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        result_resp.raise_for_status()
        stats = result_resp.json()["data"]["attributes"]["stats"]
        result = {
            "vt_malicious":  stats.get("malicious",  0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless":   stats.get("harmless",   0),
            "vt_undetected": stats.get("undetected", 0),
        }
        log.info("VT result for '%s': %s", url, result)
        return result
    except Exception as exc:
        log.warning("VT result fetch failed for '%s': %s", url, exc)

    # ── Fallback: try to read cached result by URL-id ──────────────────────────
    try:
        cached_resp = requests.get(
            f"{_VT_BASE}/urls/{_url_id(url)}",
            headers={"x-apikey": VT_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        cached_resp.raise_for_status()
        stats = cached_resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "vt_malicious":  stats.get("malicious",  0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless":   stats.get("harmless",   0),
            "vt_undetected": stats.get("undetected", 0),
        }
    except Exception as exc:
        log.warning("VT cached lookup failed for '%s': %s", url, exc)

    return dict(_DEFAULT_RESULT)

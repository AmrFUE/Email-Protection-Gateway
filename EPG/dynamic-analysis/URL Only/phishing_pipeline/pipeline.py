"""
pipeline.py — Orchestrator that chains all analysis stages together.

Call analyze_url(url) to get the full feature report dict for one URL.
Each stage is called independently; errors in one stage do not abort others.
"""

from __future__ import annotations

from .logger import get_logger
from .url_normalizer import normalize_url
from .reputation import check_virustotal
from .domain_intel import analyze_domain
from .static_analysis import analyze_static
from .redirect_graph import analyze_redirects
from .dynamic_analysis import analyze_dynamic

log = get_logger("pipeline")


def analyze_url(url: str, skip_dynamic: bool = False) -> dict:
    """
    Run the full 10-stage phishing analysis pipeline on a single URL.

    Stages:
        1. URL normalization
        2. VirusTotal reputation check
        3. Domain intelligence
        4. Static / lexical URL analysis
        5. Redirect graph analysis
        6. Dynamic analysis (Playwright headless browser)

    Args:
        url:          Raw URL extracted from email.
        skip_dynamic: Set True to skip the Playwright stage (e.g. for batch
                      analysis where browser is unavailable).

    Returns:
        Flat dict merging all feature outputs plus the original URL.
    """
    log.info("=" * 60)
    log.info("Starting analysis pipeline for: %s", url)

    report: dict = {"url": url}

    # ── Stage 2: Normalize ──────────────────────────────────────────────────
    try:
        norm_url = normalize_url(url)
        report["normalized_url"] = norm_url
    except Exception as exc:
        log.error("Normalization failed: %s", exc)
        norm_url = url
        report["normalized_url"] = url

    # ── Stage 3: VirusTotal Reputation ─────────────────────────────────────
    try:
        log.info("[3/6] VirusTotal reputation check…")
        report.update(check_virustotal(norm_url))
    except Exception as exc:
        log.error("Reputation stage failed: %s", exc)
        report.update({"vt_malicious": 0, "vt_suspicious": 0,
                        "vt_harmless": 0, "vt_undetected": 0})

    # ── Stage 4: Domain Intelligence ────────────────────────────────────────
    try:
        log.info("[4/6] Domain intelligence…")
        report.update(analyze_domain(norm_url))
    except Exception as exc:
        log.error("Domain intel stage failed: %s", exc)

    # ── Stage 5: Static Analysis ────────────────────────────────────────────
    try:
        log.info("[5/6] Static URL analysis…")
        report.update(analyze_static(norm_url))
    except Exception as exc:
        log.error("Static analysis stage failed: %s", exc)

    # ── Stage 6: Redirect Graph ─────────────────────────────────────────────
    try:
        log.info("[6/6-a] Redirect chain analysis…")
        report.update(analyze_redirects(norm_url))
    except Exception as exc:
        log.error("Redirect stage failed: %s", exc)
        report.update({"phish_redirect_count": 0, "final_url": norm_url})

    # ── Stage 7–10: Dynamic Analysis (Playwright) ───────────────────────────
    if skip_dynamic:
        log.info("Dynamic analysis skipped (skip_dynamic=True).")
    else:
        try:
            log.info("[6/6-b] Dynamic analysis (headless browser)…")
            report.update(analyze_dynamic(norm_url))
        except Exception as exc:
            log.error("Dynamic analysis stage failed: %s", exc)

    log.info("Pipeline complete for: %s", url)
    return report

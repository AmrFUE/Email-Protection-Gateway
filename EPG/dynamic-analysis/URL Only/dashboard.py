"""
dashboard.py — Interactive terminal dashboard for the Phishing URL Analysis Pipeline.

Usage modes:
    1. python dashboard.py
       → prompts for email text (or a single URL), then analyses all found URLs

    2. python dashboard.py "https://example.com"
       → analyses the URL passed as first CLI argument directly

    3. Import and call programmatically:
       from dashboard import run_analysis
       results = run_analysis(email_text)
"""

from __future__ import annotations

import sys
import json
from typing import Any

from phishing_pipeline.url_extractor import extract_urls
from phishing_pipeline.pipeline import analyze_url


# ─────────────────────────────────────────────────────────────────────────────
# Terminal formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

WIDTH = 72

def _line(char: str = "─") -> str:
    return char * WIDTH

def _header(title: str, char: str = "═") -> None:
    pad = (WIDTH - len(title) - 2) // 2
    print(f"\n{char * pad} {title} {char * (WIDTH - pad - len(title) - 2)}")

def _section(title: str) -> None:
    print(f"\n  ┌─ {title} {'─' * (WIDTH - len(title) - 5)}┐")

def _row(label: str, value: Any, indent: int = 4) -> None:
    label_str = f"{' ' * indent}{label}"
    val_str = str(value)
    dots = "." * max(1, WIDTH - len(label_str) - len(val_str) - 4)
    print(f"{label_str} {dots} {val_str}")

def _risk_badge(score: int) -> str:
    if score == 0:
        return "✅  CLEAN"
    elif score <= 3:
        return "⚠️   LOW RISK"
    elif score <= 10:
        return "🔶  MEDIUM RISK"
    else:
        return "🔴  HIGH RISK  ← LIKELY PHISHING"

def _yn(val: int | float) -> str:
    return "YES" if val else "NO"


# ─────────────────────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────────────────────

def _build_risk_reasons(report: dict) -> list[str]:
    """
    Inspect every feature in the report and return a human-readable list
    of reasons WHY this URL may be malicious / suspicious.
    Returns an empty list if no risk signals are found.
    """
    reasons: list[str] = []

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_mal = report.get("vt_malicious", 0)
    vt_sus = report.get("vt_suspicious", 0)
    if vt_mal > 0:
        reasons.append(
            f"🔴  VirusTotal: {vt_mal} security engine(s) flagged this URL as "
            f"MALICIOUS. It is actively listed in threat intelligence databases."
        )
    if vt_sus > 0:
        reasons.append(
            f"🟠  VirusTotal: {vt_sus} engine(s) flagged this URL as SUSPICIOUS. "
            f"It may be newly registered or exhibit unusual behaviour."
        )

    # ── Domain ────────────────────────────────────────────────────────────────
    if report.get("phish_suspicious_tld"):
        tld = report.get("domain", "?").rsplit(".", 1)[-1]
        reasons.append(
            f"🟠  Suspicious TLD '.{tld}': Free and frequently abused TLDs are "
            f"commonly used by attackers because domains are free / anonymous."
        )
    if report.get("phish_multiple_subdomains"):
        reasons.append(
            "🟡  Multiple subdomain levels detected. Attackers add subdomains to "
            "make URLs look legitimate (e.g., 'paypal.com.stolen.tk/login')."
        )
    if report.get("phish_adv_long_domain"):
        reasons.append(
            f"🟡  Long domain name ({len(report.get('domain',''))} chars). Phishing domains "
            f"are often long to hide the real domain among keywords (e.g., "
            f"'secure-amazon-login-update.xyz')."
        )

    # ── Static / Lexical ─────────────────────────────────────────────────────
    if report.get("having_ip_address"):
        reasons.append(
            "🔴  IP address used as host instead of a domain name. Legitimate "
            "services almost never send users to raw IP addresses."
        )
    if report.get("phish_encoded_non_ascii"):
        reasons.append(
            "🔴  Percent-encoded non-ASCII characters found in URL path. "
            "Often used to obscure malicious payloads, bypass filters, or "
            "deliver defaced language content (e.g. Chinese/Cyrillic spam)."
        )
    if report.get("shortening_service"):
        reasons.append(
            "🟠  URL shortener detected. Shorteners hide the real destination "
            "and are commonly used in phishing emails and SMS."
        )
    if report.get("abnormal_url"):
        reasons.append(
            "🟡  Abnormal URL structure: the registered domain does not appear in "
            "the netloc as expected. May indicate credential embedding or IDN "
            "homograph attack."
        )
    if report.get("at_sign", 0) > 0:
        reasons.append(
            "🟠  '@' character found in URL. Browsers ignore everything before '@' "
            "in a URL, so 'http://google.com@evil.com' actually loads 'evil.com'."
        )
    hyphens = report.get("phish_adv_hyphen_count", 0)
    if isinstance(hyphens, int) and hyphens >= 3:
        reasons.append(
            f"🟡  {hyphens} hyphens in hostname. Excessive hyphens are a common "
            f"phishing indicator (e.g., 'secure-login-bank-verify.com')."
        )
    url_len = report.get("url_len", 0)
    if isinstance(url_len, int) and url_len > 100:
        reasons.append(
            f"🟡  Very long URL ({url_len} chars). Phishing URLs are often padded "
            f"with decoy parameters to confuse users and security filters."
        )

    # ── Redirect Chain ────────────────────────────────────────────────────────
    redirects = report.get("phish_redirect_count", 0)
    if isinstance(redirects, int) and redirects >= 3:
        reasons.append(
            f"🟠  {redirects} redirect hops detected. Multi-step redirect chains "
            f"are used to obscure the final phishing destination from email "
            f"security filters."
        )
    
    cross_domain = report.get("phish_cross_domain_redirects", 0)
    if isinstance(cross_domain, int) and cross_domain >= 2:
        reasons.append(
            f"🟠  {cross_domain} cross-domain redirects detected. Bouncing across "
            f"multiple different domains is a common phishing evasion tactic."
        )

    if report.get("phish_open_redirect_abuse"):
        reasons.append(
            "🔴  Open Redirect Abuse detected! A legitimate site is being abused "
            "to bounce users to another domain covertly."
        )

    # ── Dynamic / DOM ─────────────────────────────────────────────────────────
    if report.get("web_password_fields", 0) and report.get("web_ssl_valid") == 0:
        reasons.append(
            "🔴  Password field found on page with NO valid SSL certificate. "
            "Credentials entered here would be transmitted in plaintext."
        )
    if report.get("web_has_login") and not report.get("is_gov_edu"):
        if vt_mal > 0 or report.get("phish_suspicious_tld") or report.get("having_ip_address"):
            reasons.append(
                "🔴  Login / credential-harvesting form detected on a URL that is "
                "also flagged by other risk signals. HIGH confidence phishing page."
            )
    hidden = report.get("web_hidden_inputs", 0)
    if isinstance(hidden, int) and hidden >= 5:
        reasons.append(
            f"🟡  {hidden} hidden form inputs found. Excessive hidden fields are "
            f"used to silently exfiltrate session tokens and CSRF bypass data."
        )
    ext_ratio = report.get("web_ext_ratio", 0.0)
    if isinstance(ext_ratio, float) and ext_ratio > 0.7:
        reasons.append(
            f"🟡  {ext_ratio:.0%} of network requests go to external domains. "
            f"High external ratios may indicate a cloned page loading assets "
            f"from the original site to appear authentic."
        )

    # ── Defacement ────────────────────────────────────────────────────────────
    if report.get("web_defacement_detected"):
        reason_text = report.get("web_defacement_reason", "Defacement detected via DOM analysis.")
        reasons.append(
            f"🔴  Website defacement detected! {reason_text} "
            f"This site has likely been compromised by a hacker group."
        )

    # ── Download Detection ────────────────────────────────────────────────────
    if report.get("file_download_detected"):
        reasons.append(
            "🔴  Executable or archive download link detected in the page "
            "(.exe / .zip / .apk / .scr etc.). The site may attempt to "
            "deliver malware to the visitor."
        )

    return reasons


def print_report(report: dict) -> None:
    """Pretty-print a single URL analysis report to the terminal."""

    vt_malicious = report.get("vt_malicious", 0)

    _header("PHISHING URL ANALYSIS REPORT", "═")
    print(f"  {'URL analyzed':30s}: {report.get('url', 'N/A')}")
    print(f"  {'Normalized URL':30s}: {report.get('normalized_url', 'N/A')}")
    print(f"\n  {'RISK ASSESSMENT':30s}: {_risk_badge(vt_malicious)}")
    print(_line())

    # ── Reputation ────────────────────────────────────────────────────────────
    _section("🛡  VirusTotal Reputation")
    _row("Malicious engines",  report.get("vt_malicious",  "N/A"))
    _row("Suspicious engines", report.get("vt_suspicious", "N/A"))
    _row("Harmless engines",   report.get("vt_harmless",   "N/A"))
    _row("Undetected engines", report.get("vt_undetected", "N/A"))

    # ── Domain Intelligence ───────────────────────────────────────────────────
    _section("🌐  Domain Intelligence")
    _row("Registered domain",       report.get("domain", "N/A"))
    _row("Multiple subdomains",     _yn(report.get("phish_multiple_subdomains", 0)))
    _row("Long domain (>30 chars)", _yn(report.get("phish_adv_long_domain", 0)))
    _row("Suspicious TLD",          _yn(report.get("phish_suspicious_tld", 0)))
    _row("Government / Education",  _yn(report.get("is_gov_edu", 0)))

    # ── Static / Lexical Analysis ─────────────────────────────────────────────
    _section("🔬  Static URL Analysis")
    _row("URL length",              report.get("url_len", "N/A"))
    _row("'@' characters",          report.get("at_sign", "N/A"))
    _row("'?' characters",          report.get("question_mark", "N/A"))
    _row("'-' characters",          report.get("hyphen", "N/A"))
    _row("'=' characters",          report.get("equals", "N/A"))
    _row("'.' characters",          report.get("dots", "N/A"))
    _row("Digit count",             report.get("digits", "N/A"))
    _row("Letter count",            report.get("letters", "N/A"))
    _row("IP address in host",      _yn(report.get("having_ip_address", 0)))
    _row("URL shortener",           _yn(report.get("shortening_service", 0)))
    _row("Abnormal URL",            _yn(report.get("abnormal_url", 0)))
    _row("Hyphens in hostname",     report.get("phish_adv_hyphen_count", "N/A"))
    _row("Digit blocks in hostname",report.get("phish_adv_number_count", "N/A"))

    # ── Redirect Chain ────────────────────────────────────────────────────────
    _section("🔀  Redirect Chain Analysis")
    _row("Redirect hops",          report.get("phish_redirect_count", "N/A"))
    _row("Final URL",              report.get("final_url", "N/A"))
    _row("Domains involved",       report.get("phish_redirect_domains", "N/A"))
    _row("Cross-domain redirects", report.get("phish_cross_domain_redirects", "N/A"))
    _row("Open redirect abuse",    "⚠️ YES" if report.get("phish_open_redirect_abuse") else "NO")
    _row("Total redirect time",    f"{report.get('phish_redirect_time', 0)}s")
    _row("Redirect loop",          "⚠️ YES" if report.get("phish_redirect_loop") else "NO")
    
    if report.get("visual_graph"):
        _section("🕸  Redirect Graph")
        print(f"\n{report.get('visual_graph')}")

    # ── Dynamic Analysis ──────────────────────────────────────────────────────
    _section("🤖  Dynamic Analysis (Headless Browser)")
    _row("HTTP status code",    report.get("web_http_status",     "N/A"))
    _row("Page is live",        _yn(report.get("web_is_live",     0)))
    _row("SSL certificate OK",  _yn(report.get("web_ssl_valid",   0)))
    _row("Forms found",         report.get("web_forms_count",     "N/A"))
    _row("Password fields",     report.get("web_password_fields", "N/A"))
    _row("Hidden inputs",       report.get("web_hidden_inputs",   "N/A"))
    _row("Login page detected", _yn(report.get("web_has_login",   0)))
    
    # ── Defacement ────────────────────────────────────────────────────────────
    _section("☠️  Defacement Check")
    is_defaced = report.get("web_defacement_detected")
    _row("Defacement detected", "⚠️ YES" if is_defaced else "NO")
    if is_defaced:
        _row("Confidence",      report.get("web_defacement_confidence", "N/A").upper())
        _row("Reason",          report.get("web_defacement_reason", ""))

    # ── Network & External Resources ──────────────────────────────────────────
    _section("📡  Network Behaviour Analysis")
    ext_ratio = report.get("web_ext_ratio", 0)
    _row("Unique external domains", report.get("web_unique_domains",  "N/A"))
    _row("External request ratio",  f"{ext_ratio:.1%}" if isinstance(ext_ratio, float) else ext_ratio)

    # ── Download Detection ────────────────────────────────────────────────────
    _section("⬇️   Download Detection")
    _row("Suspicious download link",
         "⚠️  YES — potential dropper!" if report.get("file_download_detected") else "NO")

    # ── Screenshot ────────────────────────────────────────────────────────────
    screenshot_path = report.get("web_screenshot_path")
    if screenshot_path:
        _section("📸  Screenshot Captured")
        _row("Saved to", screenshot_path)

    # ── ⚠️  RISK ANALYSIS SUMMARY ─────────────────────────────────────────────
    reasons = _build_risk_reasons(report)
    print(f"\n  {'═' * (WIDTH - 2)}")
    if reasons:
        print(f"  ⚠️  RISK ANALYSIS SUMMARY — WHY THIS URL MAY BE DANGEROUS:")
        print(f"  {'─' * (WIDTH - 2)}")
        for i, reason in enumerate(reasons, start=1):
            # Word-wrap each reason to fit within WIDTH
            wrapped = [reason[j:j+WIDTH-8] for j in range(0, len(reason), WIDTH-8)]
            print(f"  [{i}] {wrapped[0]}")
            for continuation in wrapped[1:]:
                print(f"       {continuation}")
            print()
    else:
        print(f"  ✅  NO RISK SIGNALS DETECTED — URL appears clean based on all checks.")
    print(f"  {'═' * (WIDTH - 2)}")

    # ── JSON raw dump ─────────────────────────────────────────────────────────
    print(f"\n  {'─' * (WIDTH - 2)}")
    print("  Raw JSON report:")
    print(json.dumps(report, indent=4, default=str))
    print(_line("═"))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis(
    email_text: str,
    skip_dynamic: bool = False,
) -> list[dict]:
    """
    Extract URLs from email_text, analyse each one, and return the list
    of result dicts (one per URL).

    Args:
        email_text:    Raw email body or a plain URL string.
        skip_dynamic:  If True, skip the Playwright dynamic analysis stage.

    Returns:
        List of analysis report dicts.
    """
    urls = extract_urls(email_text)

    # Fallback 1: starts with http/https but regex didn't match
    if not urls:
        stripped = email_text.strip()
        if stripped.startswith(("http://", "https://")):
            urls = [stripped]

    # Fallback 2: bare URL with no scheme at all (e.g., just pasted from CSV)
    if not urls:
        stripped = email_text.strip().rstrip("/")
        # Looks like a domain if it has a dot and no spaces
        if "." in stripped and " " not in stripped and len(stripped) < 2048:
            candidate = "https://" + stripped
            urls = [candidate]

    if not urls:
        print("\n  ⚠️  No URLs found in the provided text.")
        print("  Tip: paste a full URL (with or without http://) or an email containing URLs.")
        return []

    print(f"\n  Found {len(urls)} URL(s) to analyse.\n")

    results: list[dict] = []
    for i, url in enumerate(urls, start=1):
        print(_line("─"))
        print(f"  Analysing URL {i}/{len(urls)}: {url}")
        print(_line("─"))
        report = analyze_url(url, skip_dynamic=skip_dynamic)
        print_report(report)
        results.append(report)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Interactive CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    WIDTH = 60

    print("=" * WIDTH)

    print(" ██   ██ ███████ ███    ██ ██████  ██    ██ ")
    print(" ██   ██ ██      ████   ██ ██   ██  ██  ██  ")
    print(" ███████ █████   ██ ██  ██ ██   ██   ████   ")
    print(" ██   ██ ██      ██  ██ ██ ██   ██    ██    ")
    print(" ██   ██ ███████ ██   ████ ██████     ██    ")

    print("\n  URL Analysis Engine v1.0")

    print("=" * WIDTH)


if __name__ == "__main__":
    main()

    # CLI argument: python dashboard.py "https://..."
    if len(sys.argv) > 1:
        input_text = " ".join(sys.argv[1:])
        print(f"\n  Input from CLI args: {input_text[:80]}…" if len(input_text) > 80 else f"\n  Input: {input_text}")
    else:
        print("\n  Paste your email text below and press Enter twice")
        print("  (or type a single URL and press Enter):\n")
        lines: list[str] = []
        try:
            while True:
                line = input()
                if line == "" and lines and lines[-1] == "":
                    break
                lines.append(line)
        except EOFError:
            pass
        input_text = "\n".join(lines)

    if not input_text.strip():
        print("\n  ⚠️  No input provided. Exiting.")
        sys.exit(0)

    # Ask about dynamic analysis
    print("\n  Run dynamic analysis (Playwright headless browser)? [Y/n]: ", end="")
    try:
        dyn_choice = input().strip().lower()
    except EOFError:
        dyn_choice = "y"
    skip_dyn = dyn_choice in ("n", "no")

    run_analysis(input_text, skip_dynamic=skip_dyn)


if __name__ == "__main__":
    main()

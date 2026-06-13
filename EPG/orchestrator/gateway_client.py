"""
gateway_client.py — KNOWHOW Sandbox Gateway Client SDK
=======================================================
Drop this file on the Gateway server. It handles the ENTIRE lifecycle
automatically — no manual API keys, no manual polling, no manual headers.

Usage (one-liner):
    from gateway_client import SandboxClient

    client = SandboxClient()              # Reads config from .env
    report = client.analyze("malware.exe") # Does EVERYTHING automatically
    print(report["unified_verdict"])

Full lifecycle handled automatically:
    1. Authenticate with API key (from .env)
    2. Upload file/URL to sandbox
    3. Poll until analysis is complete
    4. Download JSON + HTML reports
    5. Trigger soft cleanup
    6. Trigger GCP snapshot revert
    7. Wait for sandbox to come back online
    8. Return the report

Environment Variables (in .env on the Gateway):
    SANDBOX_URL          — http://<sandbox-ip>:8000
    KNOWHOW_API_KEY      — Must match the sandbox's key
    GCP_PROJECT          — GCP Project ID
    GCP_ZONE             — e.g. us-central1-a
    GCP_INSTANCE_NAME    — Sandbox VM name
    GCP_SNAPSHOT_NAME    — Clean snapshot name
    AUTO_REVERT          — "true" to auto-revert after each analysis
"""

import os
import sys
import time
import json
import logging
import requests
from pathlib import Path
from typing import Optional

# Load .env from same directory as this script
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GATEWAY] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("gateway_client")


class SandboxClient:
    """
    Fully automated Gateway ↔ Sandbox client.

    All authentication is handled internally. Just call analyze().
    """

    def __init__(
        self,
        sandbox_url: str = None,
        api_key: str = None,
        auto_revert: bool = None,
        poll_interval: int = 5,
        revert_timeout: int = 300,
    ):
        self.sandbox_url = (
            sandbox_url
            or os.environ.get("SANDBOX_URL", "http://localhost:8000")
        ).rstrip("/")

        self.api_key = (
            api_key
            or os.environ.get("KNOWHOW_API_KEY", "knowhow-default-dev-key-change-me")
        )

        self.auto_revert = (
            auto_revert
            if auto_revert is not None
            else os.environ.get("AUTO_REVERT", "false").lower() == "true"
        )

        self.poll_interval = poll_interval
        self.revert_timeout = revert_timeout

        # Auth header — automatically included in EVERY request
        self._headers = {"X-API-Key": self.api_key}

    # ─── Public API ─────────────────────────────────────────────────────

    def analyze(
        self,
        input_path: str,
        skip_dynamic: bool = False,
        save_reports_to: str = None,
    ) -> dict:
        """
        ONE-CALL full lifecycle: submit → poll → report → cleanup → revert.

        Args:
            input_path: Path to file (.eml, .exe, etc.) or a URL string.
            skip_dynamic: Skip Playwright browser analysis for URLs.
            save_reports_to: Directory to save JSON/HTML reports locally.

        Returns:
            The full analysis report dict.
        """
        t0 = time.time()

        # ── Step 1: Submit ──
        if os.path.isfile(input_path):
            job = self._submit_file(input_path, skip_dynamic)
        else:
            job = self._submit_url(input_path, skip_dynamic)

        job_id = job["job_id"]
        log.info(f"Job submitted: {job_id}")

        # ── Step 2: Poll until done ──
        result = self._poll_until_done(job_id)
        verdict = result.get("unified_verdict", {})
        log.info(
            f"Analysis complete: {verdict.get('level', '?')} "
            f"(score: {verdict.get('combined_score', '?')}/100)"
        )

        # ── Step 3: Download reports ──
        report = self._get_json_report(job_id)

        if save_reports_to:
            self._save_reports_locally(job_id, report, save_reports_to)

        # ── Step 4: Cleanup + Revert ──
        self._cleanup(job_id)

        if self.auto_revert:
            self._revert_snapshot()

        elapsed = time.time() - t0
        log.info(f"Full lifecycle completed in {elapsed:.1f}s")

        return report

    def health(self) -> dict:
        """Check if the sandbox is online."""
        try:
            r = requests.get(
                f"{self.sandbox_url}/api/v1/health",
                timeout=10,
            )
            return r.json()
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}

    def wait_until_online(self, timeout: int = None) -> bool:
        """Block until the sandbox /health responds with 200."""
        timeout = timeout or self.revert_timeout
        log.info(f"Waiting for sandbox to come online (timeout: {timeout}s)...")
        start = time.time()

        while time.time() - start < timeout:
            try:
                r = requests.get(
                    f"{self.sandbox_url}/api/v1/health",
                    timeout=5,
                )
                if r.status_code == 200:
                    log.info(f"Sandbox ONLINE (took {time.time() - start:.0f}s)")
                    return True
            except Exception:
                pass
            time.sleep(5)

        log.error(f"Sandbox did not respond within {timeout}s")
        return False

    # ─── Private Methods ────────────────────────────────────────────────

    def _submit_file(self, filepath: str, skip_dynamic: bool) -> dict:
        """Upload a file for analysis."""
        filename = os.path.basename(filepath)
        log.info(f"Submitting file: {filename}")

        with open(filepath, "rb") as f:
            resp = requests.post(
                f"{self.sandbox_url}/api/v1/analyze",
                files={"file": (filename, f)},
                data={"skip_dynamic": str(skip_dynamic).lower()},
                headers=self._headers,
                timeout=30,
            )
        resp.raise_for_status()
        return resp.json()

    def _submit_url(self, url: str, skip_dynamic: bool) -> dict:
        """Submit a URL for analysis."""
        log.info(f"Submitting URL: {url}")

        resp = requests.post(
            f"{self.sandbox_url}/api/v1/analyze",
            data={
                "url": url,
                "skip_dynamic": str(skip_dynamic).lower(),
            },
            headers=self._headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _poll_until_done(self, job_id: str, timeout: int = None) -> dict:
        """Poll /status until job is finished."""
        timeout = timeout or (int(os.environ.get("KNOWHOW_TIMEOUT", "300")) + 60)
        start = time.time()
        last_status = ""

        while time.time() - start < timeout:
            resp = requests.get(
                f"{self.sandbox_url}/api/v1/status/{job_id}",
                headers=self._headers,
                timeout=15,
            )
            data = resp.json()
            status = data.get("status", "unknown")

            if status != last_status:
                log.info(f"  Status: {status}")
                last_status = status

            if status in ("completed", "timeout", "error"):
                return data

            time.sleep(self.poll_interval)

        raise TimeoutError(f"Analysis did not finish within {timeout}s")

    def _get_json_report(self, job_id: str) -> dict:
        """Download the full JSON report."""
        resp = requests.get(
            f"{self.sandbox_url}/api/v1/report/{job_id}",
            headers=self._headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _get_html_report(self, job_id: str) -> bytes | None:
        """Download the HTML report."""
        try:
            resp = requests.get(
                f"{self.sandbox_url}/api/v1/report/{job_id}/html",
                headers=self._headers,
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.content
        except Exception:
            pass
        return None

    def _save_reports_locally(self, job_id: str, report: dict, output_dir: str):
        """Save JSON and HTML reports to a local directory."""
        out = Path(output_dir) / job_id
        out.mkdir(parents=True, exist_ok=True)

        # JSON
        json_path = out / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        log.info(f"  Saved: {json_path}")

        # HTML
        html_content = self._get_html_report(job_id)
        if html_content:
            html_path = out / "report.html"
            with open(html_path, "wb") as f:
                f.write(html_content)
            log.info(f"  Saved: {html_path}")

    def _cleanup(self, job_id: str):
        """Call the soft cleanup endpoint on the sandbox."""
        try:
            resp = requests.post(
                f"{self.sandbox_url}/api/v1/cleanup",
                headers=self._headers,
                timeout=30,
            )
            if resp.status_code == 200:
                log.info("Soft cleanup complete (dirs wiped)")
        except Exception as e:
            log.warning(f"Soft cleanup failed (non-fatal): {e}")

    def _revert_snapshot(self):
        """Trigger GCP snapshot revert and wait for sandbox to come back."""
        log.info("Triggering GCP snapshot revert...")
        try:
            # Import the revert function from gcp_revert.py
            script_dir = Path(__file__).parent
            sys.path.insert(0, str(script_dir))
            sys.path.insert(0, str(script_dir / "sandbox"))

            from gcp_revert import revert_to_snapshot
            result = revert_to_snapshot()

            if result.get("status") == "completed":
                log.info(
                    f"Snapshot revert completed in "
                    f"{result.get('total_seconds', '?')}s"
                )
                # Wait for the sandbox API to come back online
                self.wait_until_online()
            else:
                log.error(f"Revert failed: {result.get('error')}")

        except ImportError:
            log.error(
                "gcp_revert.py not found. Place it next to gateway_client.py "
                "or in the sandbox/ directory."
            )
        except Exception as e:
            log.error(f"Revert error: {e}")


# ─── CLI for quick testing ──────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="KNOWHOW Gateway Client")
    parser.add_argument("input", help="File path or URL to analyze")
    parser.add_argument("--save-to", default="./gateway_reports",
                        help="Directory to save reports")
    parser.add_argument("--no-revert", action="store_true",
                        help="Skip snapshot revert after analysis")
    parser.add_argument("--health", action="store_true",
                        help="Just check sandbox health")
    args = parser.parse_args()

    client = SandboxClient(
        auto_revert=not args.no_revert and os.environ.get("AUTO_REVERT", "false").lower() == "true"
    )

    if args.health:
        print(json.dumps(client.health(), indent=2))
        sys.exit(0)

    report = client.analyze(
        args.input,
        save_reports_to=args.save_to,
    )

    verdict = report.get("unified_verdict", {})
    print(f"\n{'='*50}")
    print(f"  VERDICT: {verdict.get('level', 'UNKNOWN')}")
    print(f"  SCORE:   {verdict.get('combined_score', '?')}/100")
    print(f"{'='*50}")

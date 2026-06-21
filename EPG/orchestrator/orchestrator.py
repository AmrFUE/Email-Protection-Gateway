"""
orchestrator.py - EPG Email Pipeline Orchestrator
===================================================
Receives emails from the SMTP milter (via Redis queue), routes them through
each detection stage in sequence, and makes the final ACCEPT/REJECT decision.

Pipeline: Spam -> Phishing -> Malware -> Dynamic -> Deliver/Quarantine

Each stage is a separate Docker container exposing a REST API.
"""

import os
import sys
import json
import time
import shutil
import logging
import tempfile
from datetime import datetime
from pathlib import Path

import redis
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EPGOrchestrator")

# ── Service URLs (internal Docker network)
SPAM_URL     = os.environ.get("SPAM_URL",     "http://spam-filter:8001")
PHISHING_URL = os.environ.get("PHISHING_URL", "http://phishing-filter:8002")
MALWARE_URL  = os.environ.get("MALWARE_URL",  "http://malware-scanner:8003")
DYNAMIC_URL  = os.environ.get("DYNAMIC_URL",  "http://dynamic-analysis:8004")

# ── PhishGuard External API (replaces internal phishing-filter)
PHISHGUARD_URL = os.environ.get("PHISHGUARD_URL", "https://4538-196-139-203-125.ngrok-free.app")

# ── Redis
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

# ── Quarantine
QUARANTINE_DIR = os.environ.get("QUARANTINE_DIR", "/data/quarantine")

# ── Database
DB_URL = os.environ.get("DATABASE_URL", "postgresql://epg:epg@database:5432/epg")


class EPGOrchestrator:
    """Orchestrates the multi-stage email scanning pipeline."""

    def __init__(self):
        self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        logger.info("EPG Orchestrator initialized.")

    def process_email(self, eml_path: str, envelope: dict) -> dict:
        """
        Process a single email through the full pipeline.
        
        Args:
            eml_path: Path to the .eml file
            envelope: Dict with 'from', 'to', 'message_id'
        
        Returns:
            Dict with final verdict and per-stage results
        """
        start_time = time.time()
        email_id = envelope.get('message_id', f"email_{int(time.time())}")

        log_entry = {
            'email_id': email_id,
            'timestamp': datetime.now().isoformat(),
            'from_email': envelope.get('from', ''),
            'to_email': envelope.get('to', ''),
            'stages': {},
            'final_verdict': 'CLEAN',
            'action': 'DELIVERED',
        }

        logger.info(f"[{email_id}] Processing: {envelope.get('from')} -> {envelope.get('to')}")

        # ── Stage 1: Static Malware Scanner
        logger.info(f"[{email_id}] Stage 1/4: Malware Scanner")
        malware_result = self._call_malware(eml_path)
        log_entry['stages']['malware'] = malware_result

        # If any attachment or URL is MALICIOUS ➔ BLOCK immediately
        if malware_result.get('overall_verdict') == 'MALICIOUS':
            log_entry['final_verdict'] = 'MALICIOUS'
            log_entry['action'] = 'BLOCKED'
            log_entry['block_reason'] = f"Static Analysis: Malicious content detected: {malware_result.get('note', '')}"
            self._quarantine(eml_path, email_id, 'malware')
            log_entry['scan_time'] = time.time() - start_time
            self._save_log(log_entry)
            return log_entry

        # If SUSPICIOUS or CLEAN ➔ Check if we have attachments or URLs to send to Dynamic
        has_items_to_scan = malware_result.get('has_attachments', False) or malware_result.get('has_urls', False)
        malware_is_suspicious = malware_result.get('overall_verdict') == 'SUSPICIOUS'

        # ── Stage 2: PhishGuard Phishing Detection (fast NLP — runs before expensive sandbox)
        logger.info(f"[{email_id}] Stage 2/4: PhishGuard Phishing Detection")
        phishing_result = self._call_phishguard(eml_path, email_id)
        log_entry['stages']['phishing'] = phishing_result

        if phishing_result.get('verdict') == 'PHISHING':
            log_entry['final_verdict'] = 'PHISHING'
            log_entry['action'] = 'BLOCKED'
            log_entry['block_reason'] = phishing_result.get('note', 'Detected as phishing')
            self._quarantine(eml_path, email_id, 'phishing')
            log_entry['scan_time'] = time.time() - start_time
            self._save_log(log_entry)
            return log_entry

        # ── Stage 3: Dynamic Analysis (expensive sandbox — only for items that passed phishing)
        dynamic_skipped = False
        if has_items_to_scan or malware_is_suspicious:
            if os.environ.get("ENABLE_DYNAMIC", "true").lower() == "true":
                logger.info(f"[{email_id}] Stage 3/4: Dynamic Analysis (Items found or Suspicious)")

                dynamic_result = self._call_dynamic(eml_path, email_id)
                log_entry['stages']['dynamic'] = dynamic_result

                # Dynamic Analysis Report dictates the final EPG decision
                if dynamic_result.get('verdict') == 'MALICIOUS':
                    log_entry['final_verdict'] = 'MALICIOUS'
                    log_entry['action'] = 'BLOCKED'
                    log_entry['block_reason'] = f"Dynamic Analysis Sandbox: Malicious behavior detected ({dynamic_result.get('note', '')})"
                    self._quarantine(eml_path, email_id, 'dynamic')
                    log_entry['scan_time'] = time.time() - start_time
                    self._save_log(log_entry)
                    return log_entry
                
                elif dynamic_result.get('verdict') == 'SUSPICIOUS':
                    log_entry['final_verdict'] = 'SUSPICIOUS'
                    log_entry['action'] = 'QUARANTINED'
                    log_entry['block_reason'] = f"Dynamic Analysis Sandbox: Suspicious behavior detected ({dynamic_result.get('note', '')})"
                    self._quarantine(eml_path, email_id, 'dynamic')
                    log_entry['scan_time'] = time.time() - start_time
                    self._save_log(log_entry)
                    return log_entry
                    
                elif dynamic_result.get('verdict') == 'SKIPPED':
                    dynamic_skipped = True
            else:
                dynamic_skipped = True

        # ── Stage 4: Spam Filter
        logger.info(f"[{email_id}] Stage 4/4: Spam Filter")
        spam_result = self._call_stage(SPAM_URL, eml_path, "spam")
        log_entry['stages']['spam'] = spam_result

        if spam_result.get('verdict') == 'SPAM':
            log_entry['final_verdict'] = 'SPAM'
            log_entry['action'] = 'TAGGED'
            log_entry['block_reason'] = spam_result.get('note', 'Detected as spam')
            self._quarantine(eml_path, email_id, 'spam')
            log_entry['scan_time'] = time.time() - start_time
            self._save_log(log_entry)
            return log_entry

        # (Suspicious spam block removed to enforce strict binary SPAM/CLEAN)

        # ── All clear — deliver (or quarantine if malware was sus but dynamic skipped)
        if malware_is_suspicious and dynamic_skipped:
            log_entry['final_verdict'] = 'SUSPICIOUS'
            log_entry['action'] = 'QUARANTINED'
            log_entry['block_reason'] = 'Static Scanner flagged as suspicious, but Dynamic Sandbox was unavailable. Requires manual SOC review.'
            self._quarantine(eml_path, email_id, 'malware_suspicious')
            log_entry['scan_time'] = time.time() - start_time
            self._save_log(log_entry)
            logger.info(f"[{email_id}] QUARANTINED — Malware SUSPICIOUS but dynamic skipped.")
            return log_entry

        log_entry['final_verdict'] = 'CLEAN'
        log_entry['action'] = 'DELIVERED'
        log_entry['scan_time'] = time.time() - start_time
        self._save_log(log_entry)

        logger.info(f"[{email_id}] CLEAN — delivering to mail server ({log_entry['scan_time']:.1f}s)")
        return log_entry

    def _call_stage(self, service_url: str, eml_path: str, stage_name: str) -> dict:
        """Call a standard synchronous detection stage REST API."""
        try:
            with open(eml_path, 'rb') as f:
                response = requests.post(
                    f"{service_url}/scan",
                    files={"file": (os.path.basename(eml_path), f)},
                    timeout=300,
                )
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"[{stage_name}] returned status {response.status_code}")
                return {"verdict": "CLEAN", "note": f"{stage_name} unavailable, defaulting to CLEAN"}
        except requests.exceptions.ConnectionError:
            logger.warning(f"[{stage_name}] service not reachable — skipping")
            return {"verdict": "CLEAN", "note": f"{stage_name} service offline"}
        except Exception as e:
            logger.error(f"[{stage_name}] error: {e}")
            return {"verdict": "CLEAN", "note": f"{stage_name} error: {str(e)}"}

    def _call_phishguard(self, eml_path: str, email_id: str) -> dict:
        """Call the external PhishGuard Phishing Detection API."""
        try:
            logger.info(f"[{email_id}] Sending to PhishGuard: {PHISHGUARD_URL}/scan")
            with open(eml_path, 'rb') as f:
                response = requests.post(
                    f"{PHISHGUARD_URL}/scan",
                    files={"file": (os.path.basename(eml_path), f)},
                    headers={"ngrok-skip-browser-warning": "true"},
                    timeout=120,
                )

            if response.status_code != 200:
                logger.warning(f"[{email_id}] PhishGuard returned status {response.status_code}")
                return {"verdict": "CLEAN", "note": f"PhishGuard unavailable ({response.status_code}), defaulting to CLEAN"}

            data = response.json()

            # ── Brief Verdict (for routing)
            verdict = data.get('verdict', 'CLEAN')
            score = data.get('score', 0)
            note = data.get('note', '')
            confidence = data.get('confidence', 0)
            action = data.get('action', 'DELIVER')

            # ── Full Detailed Report (for forensics)
            details = data.get('details', {})

            # ── Console output for real-time visibility
            logger.info(f"")
            logger.info(f"════════════════════════════════════════════════════")
            logger.info(f"[{email_id}] PhishGuard Result:")
            logger.info(f"  Verdict:    {verdict}")
            logger.info(f"  Score:      {score}/100")
            logger.info(f"  Action:     {action}")
            logger.info(f"  Confidence: {confidence}")
            if details:
                engine_scores = details.get('engine_scores', {})
                if engine_scores:
                    logger.info(f"  Engine Scores:")
                    for eng, sc in engine_scores.items():
                        logger.info(f"    {eng.capitalize():12s} {sc}")
                flags = details.get('total_flags_triggered', 0)
                duration = details.get('analysis_time_ms', 0)
                logger.info(f"  Flags:      {flags}")
                logger.info(f"  Duration:   {duration:.1f}ms")
            logger.info(f"════════════════════════════════════════════════════")
            logger.info(f"")

            result = {
                "verdict": verdict,
                "score": score,
                "note": note,
                "confidence": confidence,
                "action": action,
                "details": details,
            }
            return result

        except requests.exceptions.ConnectionError:
            logger.warning(f"[{email_id}] PhishGuard not reachable at {PHISHGUARD_URL} — skipping")
            return {"verdict": "CLEAN", "note": "PhishGuard service offline"}
        except Exception as e:
            logger.error(f"[{email_id}] PhishGuard error: {e}")
            return {"verdict": "CLEAN", "note": f"PhishGuard error: {str(e)}"}

    def _call_dynamic(self, eml_path: str, email_id: str) -> dict:
        """Call the KNOWHOW GCP Sandbox API (Async Polling)."""
        try:
            headers = {}
            if os.environ.get("DYNAMIC_API_KEY"):
                headers["x-api-key"] = os.environ.get('DYNAMIC_API_KEY')

            # 1. Submit for analysis (fast-fail timeout of 3s)
            logger.info(f"[{email_id}] Submitting to GCP Sandbox: {DYNAMIC_URL}/api/v1/analyze")
            with open(eml_path, 'rb') as f:
                submit_res = requests.post(
                    f"{DYNAMIC_URL}/api/v1/analyze",
                    files={"file": (os.path.basename(eml_path), f)},
                    headers=headers,
                    timeout=3,
                )
            
            if submit_res.status_code != 200:
                logger.warning(f"[dynamic] Submit failed: {submit_res.status_code} {submit_res.text}")
                return {"verdict": "SKIPPED", "note": f"Sandbox unavailable ({submit_res.status_code})"}
            
            job_id = submit_res.json().get("job_id")
            if not job_id:
                return {"verdict": "SKIPPED", "note": "Sandbox failed to return job_id"}

            logger.info(f"[{email_id}] GCP Sandbox Job ID: {job_id} — Polling for completion...")

            # 2. Poll for status
            for attempt in range(60): # 60 * 5s = 5 minutes max timeout
                time.sleep(5)
                status_res = requests.get(
                    f"{DYNAMIC_URL}/api/v1/status/{job_id}",
                    headers=headers,
                    timeout=10
                )
                if status_res.status_code == 200:
                    data = status_res.json()
                    status = data.get("status")
                    
                    if status == "completed":
                        # Map GCP schema to Orchestrator schema
                        is_malware = data.get("is_malware", False)
                        is_phishing = data.get("is_phishing", False)
                        risk = data.get("risk_level", "low").lower()
                        summary = data.get("verdict_summary", "Clean")

                        verdict = "CLEAN"
                        if is_malware or risk == "high":
                            verdict = "MALICIOUS"
                        elif is_phishing or risk == "medium":
                            verdict = "SUSPICIOUS"

                        logger.info(f"[{email_id}] GCP Sandbox completed: {verdict} ({summary})")
                        return {
                            "verdict": verdict, 
                            "note": summary,
                            "raw_report": data # <--- Inject the full GCP JSON report here!
                        }
                    
                    elif status == "failed":
                        logger.error(f"[{email_id}] GCP Sandbox job failed: {data.get('error')}")
                        return {"verdict": "CLEAN", "note": "Sandbox job failed internally", "raw_report": data}
                    
                    # If processing/pending, continue loop
            
            logger.warning(f"[{email_id}] GCP Sandbox timed out after 5 minutes")
            return {"verdict": "CLEAN", "note": "Sandbox timeout"}

        except requests.exceptions.RequestException as e:
            logger.warning(f"[dynamic] Connection failed: {e}")
            return {"verdict": "SKIPPED", "note": "Sandbox unavailable (connection failed)"}
        except Exception as e:
            logger.error(f"[dynamic] error: {e}")
            return {"verdict": "SKIPPED", "note": f"dynamic error: {str(e)}"}

    def _call_malware(self, eml_path: str) -> dict:
        """Call the malware scanner's /scan/eml endpoint."""
        try:
            with open(eml_path, 'rb') as f:
                response = requests.post(
                    f"{MALWARE_URL}/scan/eml",
                    files={"file": (os.path.basename(eml_path), f)},
                    timeout=120,
                )
            if response.status_code == 200:
                return response.json()
            else:
                return {"overall_verdict": "CLEAN", "note": "Malware scanner unavailable"}
        except Exception as e:
            logger.error(f"[malware] error: {e}")
            return {"overall_verdict": "CLEAN", "note": f"Malware scanner error: {str(e)}"}

    def _quarantine(self, eml_path: str, email_id: str, reason: str):
        """Move email to quarantine directory."""
        dest_dir = os.path.join(QUARANTINE_DIR, reason)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, f"{email_id}.eml")
        shutil.copy2(eml_path, dest)
        logger.info(f"Quarantined: {dest}")

    def _save_log(self, log_entry: dict):
        """Save scan log to Redis (dashboard reads from here)."""
        try:
            key = f"scan_log:{log_entry['email_id']}"
            self.redis.set(key, json.dumps(log_entry), ex=86400 * 30)  # 30 days TTL
            self.redis.lpush("scan_log_list", json.dumps(log_entry))
            # Trim to last 10000 entries
            self.redis.ltrim("scan_log_list", 0, 9999)
        except Exception as e:
            logger.error(f"Failed to save log: {e}")

    def listen(self):
        """Listen for emails on the Redis queue (blocking)."""
        logger.info("Listening for emails on Redis queue 'email_queue'...")
        while True:
            try:
                # Blocking pop from queue
                _, job_data = self.redis.blpop("email_queue", timeout=5)
                if job_data:
                    job = json.loads(job_data)
                    eml_path = job.get('eml_path')
                    envelope = job.get('envelope', {})

                    if eml_path and os.path.exists(eml_path):
                        result = self.process_email(eml_path, envelope)

                        # Push result back for the milter to read
                        result_key = f"result:{envelope.get('message_id', '')}"
                        self.redis.set(result_key, json.dumps(result), ex=300)
                    else:
                        logger.warning(f"EML not found: {eml_path}")

            except TypeError:
                # blpop timeout returns None
                continue
            except KeyboardInterrupt:
                logger.info("Shutting down orchestrator.")
                break
            except redis.exceptions.TimeoutError:
                # Normal TCP timeout when idle in Docker, ignore and loop
                continue
            except redis.exceptions.ConnectionError:
                logger.warning("Redis connection dropped, reconnecting...")
                time.sleep(2)
            except Exception as e:
                if "Timeout reading from socket" in str(e):
                    continue
                logger.error(f"Queue processing error: {e}")
                time.sleep(1)


if __name__ == "__main__":
    orchestrator = EPGOrchestrator()
    orchestrator.listen()

"""
EPG Admin Dashboard — FastAPI Backend
======================================
Reads scan logs from Redis and serves the dashboard UI.

Endpoints:
  POST /login                         - authenticate (default admin/admin)
  GET  /logout                        - clear session
  GET  /api/stats                     - aggregate counts & threat breakdown
  GET  /api/logs?page&limit&filter    - paginated log list
  GET  /api/logs/{email_id}           - full detail for one email
  GET  /api/stream                    - SSE live log feed
  GET  /api/mailbox                   - list mailbox users
  GET  /api/mailbox/{user}?folder=    - list emails in folder
  GET  /                              - serve dashboard HTML
"""

import asyncio
import json
import logging
import os
import time
import base64
import hashlib
import re
import tempfile
import uuid
import httpx
from datetime import datetime
from email import message_from_bytes, policy
from typing import AsyncGenerator, List, Optional
import urllib.request

import redis.asyncio as aioredis
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
    FileResponse,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Dashboard] %(levelname)s %(message)s",
)
logger = logging.getLogger("EPG-Dashboard")

# ── Config
REDIS_HOST     = os.environ.get("REDIS_HOST",     "redis")
REDIS_PORT     = int(os.environ.get("REDIS_PORT", 6379))
MAILBOX_DIR    = os.environ.get("MAILBOX_DIR",    "/data/mailbox")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "admin")
SECRET_KEY     = os.environ.get("SECRET_KEY",     "epg-change-this-secret")
PORT           = int(os.environ.get("PORT",        8080))

app    = FastAPI(title="EPG Dashboard", docs_url=None, redoc_url=None)
signer = URLSafeTimedSerializer(SECRET_KEY)

_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _redis


# ── Auth helpers
def make_token(username: str, role: str) -> str:
    return signer.dumps({"user": username, "role": role, "ts": time.time()})

def check_token(token: str) -> dict:
    try:
        return signer.loads(token, max_age=86400)
    except (BadSignature, SignatureExpired):
        return None

def require_auth(session: Optional[str] = Cookie(default=None)):
    data = check_token(session) if session else None
    if not data:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return data

def require_admin(user_data: dict = Depends(require_auth)):
    if user_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Admin access required")
    return user_data


# ── Auth routes
@app.post("/login")
async def login(request: Request):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")
    
    # Root admin check
    if username == DASHBOARD_USER and password == DASHBOARD_PASS:
        resp = JSONResponse({"status": "ok", "role": "admin"})
        resp.set_cookie("session", make_token(username, "admin"), httponly=True, max_age=86400)
        return resp
        
    # Redis user check
    rdb = await get_redis()
    raw = await rdb.hget("dashboard_users", username)
    if raw:
        try:
            user_data = json.loads(raw)
            stored_pass = user_data.get("password", "")
            role = user_data.get("role", "analyst")
        except (json.JSONDecodeError, TypeError):
            # Backward compat: old format stored password as plain string
            stored_pass = raw
            role = "analyst"
        if stored_pass == password:
            resp = JSONResponse({"status": "ok", "role": role})
            resp.set_cookie("session", make_token(username, role), httponly=True, max_age=86400)
            logger.info(f"Login OK: {username} (role={role})")
            return resp
        
    logger.warning(f"Login FAILED for user: {username}")
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie("session")
    return resp


# ── Data routes
@app.get("/api/stats")
async def get_stats(_=Depends(require_auth)):
    rdb  = await get_redis()
    logs = await rdb.lrange("scan_log_list", 0, -1)


    total = len(logs)
    blocked = suspicious = clean = spam = phishing = malware = spam_tagged = 0

    for raw in logs:
        try:
            e = json.loads(raw)
            action  = e.get("action",        "DELIVERED")
            verdict = e.get("final_verdict",  "CLEAN")
            if action == "BLOCKED":
                blocked += 1
                if verdict == "SPAM":      spam += 1
                elif verdict == "PHISHING": phishing += 1
                elif verdict == "MALICIOUS": malware += 1
            elif action == "TAGGED":
                spam_tagged += 1
            elif action == "QUARANTINED":
                suspicious += 1
            elif action == "DELIVERED":
                # Check if any stage flagged something suspicious
                stages = e.get("stages", {})
                malware_stage = stages.get("malware", {})
                if malware_stage.get("overall_verdict") == "SUSPICIOUS":
                    suspicious += 1
                else:
                    clean += 1
            else:
                clean += 1
        except Exception:
            pass

    return {
        "total": total, "blocked": blocked,
        "suspicious": suspicious, "clean": clean, "spam_tagged": spam_tagged,
        "threats": {"spam": spam, "phishing": phishing, "malware": malware},
    }


@app.get("/api/logs")
async def get_logs(
    page:   int = 1,
    limit:  int = 50,
    filter: str = "all",
    search: Optional[str] = None,
    verdict: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    _=Depends(require_auth),
):
    rdb     = await get_redis()
    all_raw = await rdb.lrange("scan_log_list", 0, -1)

    # Parse date bounds once
    dt_from = None
    dt_to = None
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
        except ValueError:
            pass

    logs = []
    for raw in all_raw:
        try:
            e      = json.loads(raw)
            action = e.get("action", "DELIVERED")
            stages = e.get("stages", {})

            # Determine if anything was suspicious across all stages
            def is_suspicious(entry):
                if entry.get("action") == "QUARANTINED":
                    return True
                # Delivered email that had a suspicious malware result
                malware_stage = entry.get("stages", {}).get("malware", {})
                if malware_stage.get("overall_verdict") == "SUSPICIOUS":
                    return True
                return False

            if filter == "blocked"    and action != "BLOCKED":    continue
            if filter == "suspicious" and not is_suspicious(e):   continue
            if filter == "spam"       and action != "TAGGED":     continue
            if filter == "clean"      and action != "DELIVERED":  continue

            # Verdict filter
            if verdict and e.get("final_verdict", "").upper() != verdict.upper():
                continue

            # Date range filter
            if dt_from or dt_to:
                ts = e.get("timestamp", "")
                try:
                    entry_dt = datetime.fromisoformat(ts)
                    if dt_from and entry_dt < dt_from:
                        continue
                    if dt_to and entry_dt > dt_to:
                        continue
                except (ValueError, TypeError):
                    continue

            # Search filter (case-insensitive across from, to, subject)
            if search:
                s = search.lower()
                from_email = e.get("from_email", "").lower()
                to_email = e.get("to_email", "").lower()
                subj = ""
                malware_s = stages.get("malware", {})
                spam_s = stages.get("spam", {})
                if malware_s.get("email", {}).get("subject"):
                    subj = malware_s["email"]["subject"].lower()
                elif spam_s.get("details", {}).get("subject"):
                    subj = spam_s["details"]["subject"].lower()
                if s not in from_email and s not in to_email and s not in subj:
                    continue

            logs.append(e)
        except Exception:
            pass

    start = (page - 1) * limit
    return {"total": len(logs), "page": page, "limit": limit,
            "logs": logs[start: start + limit]}


@app.get("/api/logs/{email_id}")
async def get_log_detail(email_id: str, _=Depends(require_auth)):
    rdb = await get_redis()
    raw = await rdb.get(f"scan_log:{email_id}")
    if not raw:
        raise HTTPException(status_code=404, detail="Not found")
    return json.loads(raw)


@app.get("/api/stream")
async def sse_stream(_=Depends(require_auth)):
    """SSE endpoint — pushes new log entries as they arrive."""
    async def gen() -> AsyncGenerator[str, None]:
        rdb  = await get_redis()
        last = await rdb.llen("scan_log_list")
        yield 'data: {"type":"connected"}\n\n'
        while True:
            await asyncio.sleep(2)
            try:
                cur = await rdb.llen("scan_log_list")
                if cur > last:
                    new = await rdb.lrange("scan_log_list", 0, cur - last - 1)
                    for entry in new:
                        yield f"data: {entry}\n\n"
                    last = cur
                else:
                    yield 'data: {"type":"ping"}\n\n'
            except Exception as e:
                logger.error(f"SSE error: {e}")
                break

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/download/{email_id}")
async def download_email(email_id: str, _=Depends(require_auth)):
    base_dir = "/data/quarantine"
    if os.path.exists(base_dir):
        for root, _, files in os.walk(base_dir):
            if f"{email_id}.eml" in files:
                return FileResponse(
                    os.path.join(root, f"{email_id}.eml"),
                    media_type="message/rfc822",
                    filename=f"{email_id}.eml"
                )
    raise HTTPException(status_code=404, detail="Email file not found in quarantine")


@app.post("/api/action/release/{email_id}")
async def release_email(email_id: str, _=Depends(require_auth)):
    base_dir = "/data/quarantine"
    eml_path = None
    if os.path.exists(base_dir):
        for root, _, files in os.walk(base_dir):
            if f"{email_id}.eml" in files:
                eml_path = os.path.join(root, f"{email_id}.eml")
                break
    if not eml_path:
        raise HTTPException(status_code=404, detail="Email file not found")
        
    with open(eml_path, 'rb') as f:
        content = f.read()
        
    msg = message_from_bytes(content)
    
    # Extract recipients
    recipients = []
    for hdr in ['To', 'Cc']:
        vals = msg.get_all(hdr, [])
        for r in vals:
            if '<' in r:
                recipients.append(r.split('<')[1].split('>')[0])
            else:
                recipients.append(r.strip())
    
    if not recipients:
        return {"status": "error", "message": "No recipients found in email"}
    
    # Deliver via IMAP APPEND (bypasses Haraka MX check entirely)
    import imaplib
    IMAP_HOST = os.environ.get("MAILU_HOST", "mailserver")
    IMAP_PORT_NUM = int(os.environ.get("IMAP_PORT", 993))
    IMAP_USER_ADDR = os.environ.get("IMAP_USER", "admin@jawabi.app")
    IMAP_PASS_VAL = os.environ.get("IMAP_PASS", "admin123")
    
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT_NUM)
        imap.login(IMAP_USER_ADDR, IMAP_PASS_VAL)
        typ, data = imap.append(
            "INBOX", None,
            imaplib.Time2Internaldate(time.time()),
            content
        )
        imap.logout()
        if typ == 'OK':
            return {"status": "ok", "message": f"Email released to inbox for: {', '.join(recipients)}"}
        else:
            return {"status": "error", "message": f"IMAP APPEND failed: {data}"}
    except Exception as e:
        logger.error(f"Release failed: {e}")
        return {"status": "error", "message": f"IMAP delivery failed: {e}"}

@app.post("/api/action/block/{email_id}")
async def block_email(email_id: str, _=Depends(require_auth)):
    # Blocking just means we confirm the quarantine status and optionally delete the file
    # For forensic purposes, we usually leave it in quarantine. 
    return {"status": "ok", "message": "Email permanently blocked and kept in quarantine for analysis."}



# ── Settings & User Management
SETTINGS_REDIS_KEY = "epg_settings"
EPG_ENV_PATH = os.environ.get("EPG_ENV_PATH", "/data/epg-config/.env")

# API key field names that map to the .env file
API_KEY_FIELDS = ["OTX_API_KEY", "MALWAREBAZAAR_API_KEY", "URLHAUS_API_KEY", "VT_API_KEY", "ANYRUN_API_KEY"]

def read_env_file():
    """Read the mounted .env file from the malware-scanner config."""
    env_vars = {}
    path = EPG_ENV_PATH
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    env_vars[key.strip()] = val.strip()
    return env_vars

def write_env_file(env_vars):
    """Write API keys back to the mounted .env file."""
    path = EPG_ENV_PATH
    lines = []
    if os.path.exists(path):
        with open(path, "r") as f:
            lines = f.readlines()

    keys_written = set()
    for i, line in enumerate(lines):
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in env_vars:
                lines[i] = f"{k}={env_vars[k]}\n"
                keys_written.add(k)

    for k, v in env_vars.items():
        if k not in keys_written:
            lines.append(f"{k}={v}\n")

    try:
        with open(path, "w") as f:
            f.writelines(lines)
        logger.info(f"Wrote .env file: {path}")
    except Exception as e:
        logger.error(f"Failed to write .env file: {e}")

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    rdb = await get_redis()
    raw = await rdb.get(SETTINGS_REDIS_KEY)
    if raw:
        return json.loads(raw)
    # First load: try reading from the mounted .env file
    file_settings = read_env_file()
    defaults = {
        "OTX_API_KEY": "",
        "MALWAREBAZAAR_API_KEY": "",
        "URLHAUS_API_KEY": "",
        "VT_API_KEY": "",
        "ANYRUN_API_KEY": "",
        "ENABLE_DYNAMIC": "false",
        "REDIS_HOST": "redis",
        "REDIS_PORT": "6379",
        "MALWARE_PROJECT_PATH": ""
    }
    defaults.update(file_settings)
    return defaults

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_admin)):
    data = await request.json()
    rdb = await get_redis()
    # Merge with existing settings in Redis
    raw = await rdb.get(SETTINGS_REDIS_KEY)
    existing = json.loads(raw) if raw else {}
    existing.update(data)
    await rdb.set(SETTINGS_REDIS_KEY, json.dumps(existing))
    # Also write API keys to the mounted .env file
    api_updates = {k: v for k, v in data.items() if k in API_KEY_FIELDS}
    if api_updates:
        write_env_file(api_updates)
        # Notify the malware-scanner and spam-filter to reload their configs without restarting
        try:
            req1 = urllib.request.Request("http://malware-scanner:8003/reload", method="POST")
            with urllib.request.urlopen(req1, timeout=3) as response:
                logger.info(f"Notified malware-scanner to reload. Response: {response.status}")
        except Exception as e:
            logger.error(f"Failed to notify malware-scanner of config reload: {e}")
            
        try:
            req2 = urllib.request.Request("http://spam-filter:8001/reload", method="POST")
            with urllib.request.urlopen(req2, timeout=3) as response:
                logger.info(f"Notified spam-filter to reload. Response: {response.status}")
        except Exception as e:
            logger.error(f"Failed to notify spam-filter of config reload: {e}")
            
    logger.info(f"Settings saved: {list(data.keys())}")
    return {"status": "ok"}

@app.get("/api/users")
async def get_users(_=Depends(require_admin)):
    rdb = await get_redis()
    users = await rdb.hgetall("dashboard_users")
    # Return list of usernames, plus the root admin
    user_list = [{"username": DASHBOARD_USER, "role": "admin"}]
    for u, raw in users.items():
        try:
            user_data = json.loads(raw)
            role = user_data.get("role", "analyst")
        except (json.JSONDecodeError, TypeError):
            role = "analyst"
        user_list.append({"username": u, "role": role})
    return user_list

@app.post("/api/users")
async def add_user(request: Request, _=Depends(require_admin)):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "analyst")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing username or password")
    if username == DASHBOARD_USER:
        raise HTTPException(status_code=400, detail="Cannot overwrite root admin")
    if role not in ("admin", "analyst"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'analyst'")
    rdb = await get_redis()
    user_data = json.dumps({"password": password, "role": role})
    await rdb.hset("dashboard_users", username, user_data)
    logger.info(f"User created: {username} (role={role})")
    return {"status": "ok"}

@app.put("/api/users/{username}")
async def update_user(username: str, request: Request, _=Depends(require_admin)):
    if username == DASHBOARD_USER:
        raise HTTPException(status_code=400, detail="Cannot modify root admin")
    rdb = await get_redis()
    raw = await rdb.hget("dashboard_users", username)
    if not raw:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        user_data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        user_data = {"password": raw}
    data = await request.json()
    if "role" in data:
        if data["role"] not in ("admin", "analyst"):
            raise HTTPException(status_code=400, detail="Role must be 'admin' or 'analyst'")
        user_data["role"] = data["role"]
    if "password" in data and data["password"]:
        user_data["password"] = data["password"]
    await rdb.hset("dashboard_users", username, json.dumps(user_data))
    logger.info(f"User updated: {username} -> {user_data.get('role')}")
    return {"status": "ok"}

@app.delete("/api/users/{username}")
async def delete_user(username: str, _=Depends(require_admin)):
    if username == DASHBOARD_USER:
        raise HTTPException(status_code=400, detail="Cannot delete root admin")
    rdb = await get_redis()
    await rdb.hdel("dashboard_users", username)
    logger.info(f"User deleted: {username}")
    return {"status": "ok"}


# ── Quarantine Management
def _extract_subject(entry: dict) -> str:
    """Extract email subject from scan log stages."""
    stages = entry.get("stages", {})
    malware_s = stages.get("malware", {})
    spam_s = stages.get("spam", {})
    subj = malware_s.get("email", {}).get("subject", "")
    if not subj:
        subj = spam_s.get("details", {}).get("subject", "")
    return subj or "(no subject)"


def _extract_score(entry: dict) -> Optional[float]:
    """Extract a threat score from stages if available."""
    stages = entry.get("stages", {})
    spam_s = stages.get("spam", {})
    score = spam_s.get("details", {}).get("score")
    if score is not None:
        return score
    malware_s = stages.get("malware", {})
    score = malware_s.get("score")
    return score


def _find_eml_path(email_id: str) -> Optional[str]:
    """Locate a .eml file in /data/quarantine by email_id."""
    base_dir = "/data/quarantine"
    if os.path.exists(base_dir):
        for root, _, files in os.walk(base_dir):
            if f"{email_id}.eml" in files:
                return os.path.join(root, f"{email_id}.eml")
    return None


@app.get("/api/quarantine")
async def list_quarantine(
    page: int = 1,
    limit: int = 20,
    category: str = "all",
    _=Depends(require_auth),
):
    """List quarantined / tagged / blocked emails with optional category filter."""
    rdb = await get_redis()
    all_raw = await rdb.lrange("scan_log_list", 0, -1)

    QUARANTINE_ACTIONS = {"QUARANTINED", "TAGGED", "BLOCKED"}
    CATEGORY_MAP = {
        "spam":       "SPAM",
        "phishing":   "PHISHING",
        "malware":    "MALICIOUS",
        "suspicious": "SUSPICIOUS",
    }

    items = []
    for raw in all_raw:
        try:
            e = json.loads(raw)
            action = e.get("action", "DELIVERED")
            if action not in QUARANTINE_ACTIONS:
                continue

            verdict = e.get("final_verdict", "CLEAN").upper()
            if category != "all":
                expected = CATEGORY_MAP.get(category)
                if expected and verdict != expected:
                    continue

            items.append({
                "email_id":      e.get("email_id", ""),
                "timestamp":     e.get("timestamp", ""),
                "from_email":    e.get("from_email", ""),
                "to_email":      e.get("to_email", ""),
                "subject":       _extract_subject(e),
                "final_verdict": e.get("final_verdict", "CLEAN"),
                "action":        action,
                "scan_time":     e.get("scan_time", 0),
                "score":         _extract_score(e),
            })
        except Exception:
            pass

    total = len(items)
    start = (page - 1) * limit
    return {"total": total, "page": page, "limit": limit,
            "items": items[start: start + limit]}


@app.delete("/api/quarantine/{email_id}")
async def delete_quarantine_email(email_id: str, _=Depends(require_auth)):
    """Delete a quarantined email's .eml file and remove its Redis log entry."""
    # Delete the .eml file
    eml_path = _find_eml_path(email_id)
    if eml_path:
        try:
            os.remove(eml_path)
            logger.info(f"Deleted quarantine file: {eml_path}")
        except OSError as exc:
            logger.error(f"Failed to delete {eml_path}: {exc}")
            raise HTTPException(status_code=500, detail=f"Failed to delete file: {exc}")

    # Remove matching entry from Redis scan_log_list
    rdb = await get_redis()
    all_raw = await rdb.lrange("scan_log_list", 0, -1)
    removed = False
    for raw in all_raw:
        try:
            e = json.loads(raw)
            if e.get("email_id") == email_id:
                await rdb.lrem("scan_log_list", 1, raw)
                removed = True
                break
        except Exception:
            pass

    # Also remove the individual detail key
    await rdb.delete(f"scan_log:{email_id}")

    if not eml_path and not removed:
        raise HTTPException(status_code=404, detail="Email not found in quarantine")

    logger.info(f"Quarantine entry deleted: {email_id}")
    return {"status": "ok", "message": f"Quarantined email {email_id} deleted successfully"}


@app.get("/api/quarantine/preview/{email_id}")
async def preview_quarantine_email(email_id: str, _=Depends(require_auth)):
    """Parse and return the email headers and body for preview."""
    eml_path = _find_eml_path(email_id)
    if not eml_path:
        raise HTTPException(status_code=404, detail="Email file not found in quarantine")

    with open(eml_path, "rb") as f:
        msg = message_from_bytes(f.read(), policy=policy.default)

    # Extract headers
    headers = {}
    for key in msg.keys():
        headers[key] = msg[key]

    # Extract body parts
    body_text = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and not body_text:
                body_text = part.get_content()
            elif ct == "text/html" and not body_html:
                body_html = part.get_content()
    else:
        ct = msg.get_content_type()
        content = msg.get_content()
        if ct == "text/html":
            body_html = content
        else:
            body_text = content

    return {
        "email_id":  email_id,
        "subject":   msg.get("Subject", ""),
        "from":      msg.get("From", ""),
        "to":        msg.get("To", ""),
        "date":      msg.get("Date", ""),
        "body_text": body_text or "",
        "body_html": body_html or "",
        "headers":   headers,
    }


@app.post("/api/quarantine/bulk")
async def bulk_quarantine_action(request: Request, _=Depends(require_auth)):
    """Perform release or delete on multiple quarantined emails."""
    data = await request.json()
    action = data.get("action")
    email_ids = data.get("email_ids", [])

    if action not in ("release", "delete"):
        raise HTTPException(status_code=400, detail="action must be 'release' or 'delete'")
    if not email_ids or not isinstance(email_ids, list):
        raise HTTPException(status_code=400, detail="email_ids must be a non-empty list")

    processed = 0
    errors = []

    for eid in email_ids:
        try:
            if action == "delete":
                # Inline delete logic
                eml_path = _find_eml_path(eid)
                if eml_path:
                    os.remove(eml_path)
                rdb = await get_redis()
                all_raw = await rdb.lrange("scan_log_list", 0, -1)
                for raw in all_raw:
                    try:
                        e = json.loads(raw)
                        if e.get("email_id") == eid:
                            await rdb.lrem("scan_log_list", 1, raw)
                            break
                    except Exception:
                        pass
                await rdb.delete(f"scan_log:{eid}")
                processed += 1
            elif action == "release":
                # Delegate to the existing release endpoint logic
                eml_path = _find_eml_path(eid)
                if not eml_path:
                    errors.append({"email_id": eid, "error": "File not found"})
                    continue
                with open(eml_path, "rb") as f:
                    content = f.read()
                import imaplib
                IMAP_HOST = os.environ.get("MAILU_HOST", "mailserver")
                IMAP_PORT_NUM = int(os.environ.get("IMAP_PORT", 993))
                IMAP_USER_ADDR = os.environ.get("IMAP_USER", "admin@jawabi.app")
                IMAP_PASS_VAL = os.environ.get("IMAP_PASS", "admin123")
                imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT_NUM)
                imap.login(IMAP_USER_ADDR, IMAP_PASS_VAL)
                typ, _ = imap.append(
                    "INBOX", None,
                    imaplib.Time2Internaldate(time.time()),
                    content,
                )
                imap.logout()
                if typ == "OK":
                    processed += 1
                else:
                    errors.append({"email_id": eid, "error": "IMAP APPEND failed"})
        except Exception as exc:
            errors.append({"email_id": eid, "error": str(exc)})

    return {"status": "ok", "processed": processed, "errors": errors}

# ── Scan EML ──────────────────────────────────────────

@app.get("/api/scan/eml/services")
async def check_eml_services(_=Depends(require_auth)):
    """Check health of all 4 detection layers."""
    services = {
        "malware": {"url": "http://malware-scanner:8003/health", "status": "unknown"},
        "dynamic": {"url": os.environ.get("DYNAMIC_URL", "http://dynamic-analysis:8004") + "/api/v1/health", "status": "unknown"},
        "phishing": {"url": os.environ.get("PHISHGUARD_URL", "https://ad09-196-139-203-125.ngrok-free.app") + "/health", "status": "unknown"},
        "spam": {"url": "http://spam-filter:8001/health", "status": "unknown"}
    }
    
    async with httpx.AsyncClient(timeout=2.0) as client:
        for name, svc in services.items():
            try:
                if name == "dynamic":
                    headers = {}
                    if os.environ.get("DYNAMIC_API_KEY"):
                        headers["x-api-key"] = os.environ.get("DYNAMIC_API_KEY")
                    r = await client.get(svc["url"], headers=headers)
                else:
                    r = await client.get(svc["url"])
                svc["status"] = "online" if r.status_code == 200 else "error"
            except Exception:
                svc["status"] = "offline"
                
    return {k: v["status"] for k, v in services.items()}


@app.post("/api/scan/eml")
async def scan_eml(file: UploadFile = File(...), _=Depends(require_auth)):
    """
    Parse an EML file, perform header security analysis, and route it through 
    the full EPG pipeline: Malware -> Dynamic -> Phishing -> Spam.
    """
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
        
    start_time = time.time()
    msg = message_from_bytes(content, policy=policy.default)
    
    # 1. Parsing & Header Security Analysis
    headers = {
        "From": str(msg.get("From", "")),
        "To": str(msg.get("To", "")),
        "Subject": str(msg.get("Subject", "")),
        "Date": str(msg.get("Date", "")),
        "Message-ID": str(msg.get("Message-ID", "")),
        "Reply-To": str(msg.get("Reply-To", "")),
        "Return-Path": str(msg.get("Return-Path", "")),
    }
    
    received_chain = msg.get_all("Received", [])
    auth_results = str(msg.get("Authentication-Results", ""))
    
    header_analysis = {
        "spf": "pass" if "spf=pass" in auth_results.lower() else "fail" if "spf=fail" in auth_results.lower() else "unknown",
        "dkim": "pass" if "dkim=pass" in auth_results.lower() else "fail" if "dkim=fail" in auth_results.lower() else "unknown",
        "dmarc": "pass" if "dmarc=pass" in auth_results.lower() else "fail" if "dmarc=fail" in auth_results.lower() else "unknown",
        "hop_count": len(received_chain),
        "received_chain": [str(r) for r in received_chain],
        "findings": []
    }
    
    # Simple Header Checks
    if not headers.get("Message-ID"):
        header_analysis["findings"].append({"severity": "warning", "message": "Missing Message-ID header"})
    if not headers.get("Date"):
        header_analysis["findings"].append({"severity": "warning", "message": "Missing Date header"})
        
    # Mismatches
    from_header = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")
    
    # Extract email address using regex
    email_re = re.compile(r'<([^>]+)>')
    from_match = email_re.search(from_header)
    from_email = from_match.group(1).strip().lower() if from_match else from_header.strip().lower()
    
    if reply_to:
        rt_match = email_re.search(reply_to)
        rt_email = rt_match.group(1).strip().lower() if rt_match else reply_to.strip().lower()
        if rt_email and from_email and rt_email != from_email:
            header_analysis["findings"].append({"severity": "warning", "message": f"Reply-To ({rt_email}) differs from From address ({from_email})"})
            
    if return_path:
        rp_match = email_re.search(return_path)
        rp_email = rp_match.group(1).strip().lower() if rp_match else return_path.strip().lower()
        from_domain = from_email.split('@')[-1] if '@' in from_email else ""
        rp_domain = rp_email.split('@')[-1] if '@' in rp_email else ""
        if from_domain and rp_domain and from_domain != rp_domain:
            header_analysis["findings"].append({"severity": "warning", "message": f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})"})
            
    # Auth failures
    if header_analysis["spf"] == "fail":
        header_analysis["findings"].append({"severity": "critical", "message": "SPF authentication failed"})
    if header_analysis["dkim"] == "fail":
        header_analysis["findings"].append({"severity": "critical", "message": "DKIM signature validation failed"})
    if header_analysis["dmarc"] == "fail":
        header_analysis["findings"].append({"severity": "critical", "message": "DMARC policy evaluation failed"})
        
    # Extract Body & URLs for display
    plain_text = ""
    html_text = ""
    attachments_info = []
    
    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))
        
        if part.get_content_maintype() == 'multipart':
            continue
            
        is_attachment = "attachment" in disposition or "inline" in disposition or content_type not in ('text/plain', 'text/html')
        
        if is_attachment:
            filename = part.get_filename() or "unnamed_attachment"
            payload = part.get_payload(decode=True) or b""
            attachments_info.append({
                "filename": filename,
                "content_type": content_type,
                "size": len(payload),
                "hash": hashlib.sha256(payload).hexdigest()
            })
        else:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or 'utf-8'
            try:
                decoded = payload.decode(charset, errors='replace')
            except:
                decoded = payload.decode('utf-8', errors='replace')
                
            if content_type == 'text/html':
                html_text += decoded
            elif content_type == 'text/plain':
                plain_text += decoded
                
    # Extract URLs
    url_pattern = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
    urls = list(set(url_pattern.findall(plain_text) + url_pattern.findall(html_text)))
    
    email_metadata = {
        "headers": headers,
        "header_analysis": header_analysis,
        "attachments": attachments_info,
        "urls": urls
    }
    
    # 2. Pipeline Routing
    stages = {}
    final_verdict = "CLEAN"
    
    async def call_service(url, file_content, filename):
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                files = {"file": (filename, file_content, "message/rfc822")}
                r = await client.post(url, files=files)
                if r.status_code == 200:
                    return r.json()
                return {"verdict": "ERROR", "overall_verdict": "ERROR", "note": f"Service returned {r.status_code}"}
            except Exception as e:
                return {"verdict": "ERROR", "overall_verdict": "ERROR", "note": f"Connection error: {str(e)}"}
                
    # A. Malware Scanner (8003)
    malware_res = await call_service("http://malware-scanner:8003/scan/eml", content, file.filename)
    stages["malware"] = malware_res
    
    if malware_res.get("overall_verdict") == "MALICIOUS":
        final_verdict = "MALICIOUS"
    else:
        # B. Dynamic Sandbox (if needed)
        has_items = malware_res.get("has_attachments") or malware_res.get("has_urls")
        is_suspicious = malware_res.get("overall_verdict") == "SUSPICIOUS"
        dynamic_skipped = True
        
        if has_items or is_suspicious:
            dynamic_url = os.environ.get("DYNAMIC_URL", "http://dynamic-analysis:8004")
            dynamic_api_key = os.environ.get("DYNAMIC_API_KEY", "")
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                try:
                    req_headers = {"x-api-key": dynamic_api_key} if dynamic_api_key else {}
                    files = {"file": (file.filename, content, "message/rfc822")}
                    submit_r = await client.post(f"{dynamic_url}/api/v1/analyze", files=files, headers=req_headers)
                    
                    if submit_r.status_code == 200:
                        job_id = submit_r.json().get("job_id")
                        if job_id:
                            stages["dynamic"] = {"verdict": "PENDING", "note": "Polling sandbox..."}
                            for _ in range(6):
                                await asyncio.sleep(5)
                                status_r = await client.get(f"{dynamic_url}/api/v1/status/{job_id}", headers=req_headers)
                                if status_r.status_code == 200:
                                    data = status_r.json()
                                    if data.get("status") == "completed":
                                        is_mal = data.get("is_malware", False)
                                        is_phish = data.get("is_phishing", False)
                                        risk = data.get("risk_level", "low").lower()
                                        
                                        v = "CLEAN"
                                        if is_mal or risk == "high": v = "MALICIOUS"
                                        elif is_phish or risk == "medium": v = "SUSPICIOUS"
                                        
                                        stages["dynamic"] = {
                                            "verdict": v,
                                            "note": data.get("verdict_summary", "Completed"),
                                            "raw_report": data
                                        }
                                        dynamic_skipped = False
                                        break
                                    elif data.get("status") == "failed":
                                        stages["dynamic"] = {"verdict": "ERROR", "note": "Sandbox job failed"}
                                        break
                            
                            if stages["dynamic"].get("verdict") == "PENDING":
                                stages["dynamic"] = {"verdict": "SKIPPED", "note": "Sandbox timed out after 30s"}
                    else:
                        stages["dynamic"] = {"verdict": "SKIPPED", "note": f"Sandbox submit failed: {submit_r.status_code}"}
                except Exception as e:
                    stages["dynamic"] = {"verdict": "SKIPPED", "note": f"Sandbox error: {str(e)}"}
                    
        if stages.get("dynamic", {}).get("verdict") == "MALICIOUS":
            final_verdict = "MALICIOUS"
        elif stages.get("dynamic", {}).get("verdict") == "SUSPICIOUS":
            final_verdict = "SUSPICIOUS"
        else:
            # C. PhishGuard Phishing Detection
            phishguard_url = os.environ.get("PHISHGUARD_URL", "https://ad09-196-139-203-125.ngrok-free.app")
            async with httpx.AsyncClient(timeout=120.0) as client:
                try:
                    files = {"file": (file.filename, content, "message/rfc822")}
                    r = await client.post(f"{phishguard_url}/analyze", files=files)
                    if r.status_code == 200:
                        phishing_res = r.json()
                    else:
                        phishing_res = {"verdict": "CLEAN", "note": f"PhishGuard returned {r.status_code}"}
                except Exception as e:
                    phishing_res = {"verdict": "CLEAN", "note": f"PhishGuard error: {str(e)}"}
            stages["phishing"] = phishing_res
            
            if phishing_res.get("verdict") == "PHISHING":
                final_verdict = "PHISHING"
            else:
                # D. Spam Filter (8001)
                spam_res = await call_service("http://spam-filter:8001/scan", content, file.filename)
                stages["spam"] = spam_res
                
                if spam_res.get("verdict") == "SPAM":
                    final_verdict = "SPAM"
                elif spam_res.get("verdict") == "SUSPICIOUS":
                    final_verdict = "SUSPICIOUS"
                elif is_suspicious and dynamic_skipped:
                    final_verdict = "SUSPICIOUS"
                    
    return {
        "email_metadata": email_metadata,
        "stages": stages,
        "final_verdict": final_verdict,
        "scan_time": time.time() - start_time
    }


# ── Serve HTML
@app.get("/{path:path}", response_class=HTMLResponse)
async def serve_html(path: str, session: Optional[str] = Cookie(default=None)):
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(html_path):
        return HTMLResponse(open(html_path, encoding="utf-8").read())
    return HTMLResponse("<h1>index.html missing</h1>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)

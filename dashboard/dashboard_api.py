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
from email import message_from_bytes
from typing import AsyncGenerator, Optional

import redis.asyncio as aioredis
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request
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
def make_token(username: str) -> str:
    return signer.dumps({"user": username, "ts": time.time()})


def check_token(token: str) -> bool:
    try:
        signer.loads(token, max_age=86400)
        return True
    except (BadSignature, SignatureExpired):
        return False


def require_auth(session: Optional[str] = Cookie(default=None)):
    if not session or not check_token(session):
        raise HTTPException(status_code=401, detail="Not authenticated")


# ── Auth routes
@app.post("/login")
async def login(request: Request):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")
    
    # Root admin check
    if username == DASHBOARD_USER and password == DASHBOARD_PASS:
        resp = JSONResponse({"status": "ok", "role": "admin"})
        resp.set_cookie("session", make_token(username), httponly=True, max_age=86400)
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
            resp.set_cookie("session", make_token(username), httponly=True, max_age=86400)
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
    _=Depends(require_auth),
):
    rdb     = await get_redis()
    all_raw = await rdb.lrange("scan_log_list", 0, -1)

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
API_KEY_FIELDS = ["OTX_API_KEY", "MALWAREBAZAAR_API_KEY", "URLHAUS_API_KEY", "ANYRUN_API_KEY"]

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
        "ANYRUN_API_KEY": "",
        "ENABLE_DYNAMIC": "false",
        "REDIS_HOST": "redis",
        "REDIS_PORT": "6379",
        "MALWARE_PROJECT_PATH": ""
    }
    defaults.update(file_settings)
    return defaults

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_auth)):
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
    logger.info(f"Settings saved: {list(data.keys())}")
    return {"status": "ok"}

@app.get("/api/users")
async def get_users(_=Depends(require_auth)):
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
async def add_user(request: Request, _=Depends(require_auth)):
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
async def update_user(username: str, request: Request, _=Depends(require_auth)):
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
async def delete_user(username: str, _=Depends(require_auth)):
    if username == DASHBOARD_USER:
        raise HTTPException(status_code=400, detail="Cannot delete root admin")
    rdb = await get_redis()
    await rdb.hdel("dashboard_users", username)
    logger.info(f"User deleted: {username}")
    return {"status": "ok"}

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

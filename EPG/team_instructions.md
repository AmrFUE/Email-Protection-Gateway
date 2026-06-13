# EPG Integration — What Each Team Member Needs To Do

## The Big Picture

We're building an **Email Protection Gateway** on a Contabo Linux VPS. Each of our 4 projects becomes a **Docker container** that talks via REST API. Emails flow through: **Spam → Phishing → Malware → Dynamic**. If any stage flags it, the email gets blocked.

I've built the EPG orchestrator that connects everything together. **All you need to give me is:**

---

## What You Need To Deliver

### 1. Your project code (as-is)

### 2. A `Dockerfile` (simple — just copy this template)

```dockerfile
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 800X   # 8001 for Spam, 8002 for Phishing, 8004 for Dynamic
CMD ["python", "api_server.py"]
```

### 3. An `api_server.py` with exactly 2 endpoints

Your API must have these **two endpoints** — the orchestrator calls them:

```python
from fastapi import FastAPI, UploadFile, File
import uvicorn

app = FastAPI()

@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    """
    Receive a .eml email file, analyze it, return verdict.
    """
    # Save the uploaded file
    content = await file.read()
    
    # ... YOUR DETECTION LOGIC HERE ...
    
    # Return this exact format:
    return {
        "verdict": "SPAM",       # or "HAM" / "PHISHING" / "CLEAN" / "MALICIOUS"
        "score": 87.5,           # 0-100 confidence
        "note": "Why it was flagged",
        "details": { }           # Any extra info you want to include
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "your-service-name"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=800X)  # Your port number
```

---

## Per-Member Details

### Member 1 — Spam Filter (Port 8001)
- **Input:** Full `.eml` file
- **What to extract:** Email headers (From, Reply-To, Received chain, SPF/DKIM), body text
- **Verdict values:** `"SPAM"` or `"HAM"`
- **I built `eml_parser.py`** — use it to extract headers and body:
  ```python
  from eml_parser import extract_headers, extract_body
  headers = extract_headers("email.eml")  # Returns from, to, spf_pass, dkim_pass, etc.
  body = extract_body("email.eml")        # Returns plain_text, html_text, urls
  ```

### Member 2 — Phishing Filter (Port 8002)
- **Input:** Full `.eml` file
- **What to extract:** URLs from body/HTML, sender vs display name, domain similarity
- **Verdict values:** `"PHISHING"` or `"CLEAN"`
- **Use `eml_parser.py`** to get URLs:
  ```python
  body = extract_body("email.eml")
  urls = body['urls']  # List of all URLs found in the email
  ```

### Member 3 — Static Malware (Me) (Port 8003)
- Already done and integrated.

### Member 4 — Dynamic Analysis (Port 8004)
- **Input:** Suspicious attachment files (files that scored 40-74 in my scanner)
- **Verdict values:** `"MALICIOUS"` or `"CLEAN"`
- **Recommendation:** Use ANY.RUN or Hybrid Analysis cloud API — don't run a local Windows VM (not enough RAM)

---

## Install FastAPI (Everyone)

```bash
pip install fastapi uvicorn python-multipart
```

---

## How To Test Your API Locally (Before Docker)

```bash
# Start your API
python api_server.py

# In another terminal, test with a sample .eml file:
curl -X POST http://localhost:8001/scan -F "file=@test_email.eml"
```

---

## Timeline

1. **Each person:** Build your `api_server.py` + `Dockerfile` → send to me
2. **Me:** Drop them into the EPG project, uncomment in `docker-compose.yml`
3. **Together:** Test with `docker-compose up --build`
4. **Deploy:** Push to Contabo VPS

---

## 🤖 AI Agent Prompt (Copy the one for YOUR role)

If you're using an AI coding assistant, paste the relevant prompt below along with this entire file for full context. It will generate everything you need.

---

### Prompt for Member 1 — Spam Filter

```
I'm building a Spam Filter microservice for an Email Protection Gateway (EPG). Read the full team instructions file I've attached for context.

My role is Member 1 — Spam Filter on port 8001.

I need you to create 3 files in my project directory:

1. `api_server.py` — A FastAPI server with:
   - POST /scan — Accepts a .eml file upload, runs my spam detection logic on it, and returns JSON: {"verdict": "SPAM" or "HAM", "score": 0-100, "note": "reason", "details": {}}
   - GET /health — Returns {"status": "healthy", "service": "spam-filter"}
   - Runs on port 8001
   - The /scan endpoint should: save the uploaded .eml to a temp file, extract headers (From, Reply-To, SPF/DKIM results, Received chain) and body text, run them through my detection model/logic, then return the verdict.

2. `Dockerfile` — Based on python:3.13-slim, installs requirements.txt, copies everything, exposes 8001, runs api_server.py.

3. `requirements.txt` — All Python dependencies including fastapi, uvicorn, python-multipart, plus whatever my ML model or detection logic needs.

Important rules:
- The API response format MUST match exactly: {"verdict", "score", "note", "details"}
- The /scan endpoint receives the raw .eml file as a multipart upload (parameter name: "file")
- Use tempfile for safe file handling, clean up after scanning
- Load any ML models ONCE at startup (lifespan), not per-request
- The orchestrator will call my service at http://spam-filter:8001/scan
```

---

### Prompt for Member 2 — Phishing Filter

```
I'm building a Phishing Filter microservice for an Email Protection Gateway (EPG). Read the full team instructions file I've attached for context.

My role is Member 2 — Phishing Filter on port 8002.

I need you to create 3 files in my project directory:

1. `api_server.py` — A FastAPI server with:
   - POST /scan — Accepts a .eml file upload, analyzes it for phishing indicators, and returns JSON: {"verdict": "PHISHING" or "CLEAN", "score": 0-100, "note": "reason", "details": {}}
   - GET /health — Returns {"status": "healthy", "service": "phishing-filter"}
   - Runs on port 8002
   - The /scan endpoint should: save the uploaded .eml to a temp file, extract URLs from the body/HTML, analyze sender vs display name mismatches, check domain similarity (typosquatting), run detection logic, then return the verdict.

2. `Dockerfile` — Based on python:3.13-slim, installs requirements.txt, copies everything, exposes 8002, runs api_server.py.

3. `requirements.txt` — All Python dependencies including fastapi, uvicorn, python-multipart, plus whatever my ML model or detection logic needs.

Important rules:
- The API response format MUST match exactly: {"verdict", "score", "note", "details"}
- The /scan endpoint receives the raw .eml file as a multipart upload (parameter name: "file")
- Use tempfile for safe file handling, clean up after scanning
- Load any ML models ONCE at startup (lifespan), not per-request
- The orchestrator will call my service at http://phishing-filter:8002/scan
```

---

### Prompt for Member 4 — Dynamic Analysis

```
I'm building a Dynamic Analysis microservice for an Email Protection Gateway (EPG). Read the full team instructions file I've attached for context.

My role is Member 4 — Dynamic Analysis on port 8004.

I need you to create 3 files in my project directory:

1. `api_server.py` — A FastAPI server with:
   - POST /scan — Accepts a suspicious file upload (not .eml — these are already-extracted attachments that scored SUSPICIOUS 40-74 in the static malware scanner). Submits the file to a cloud sandbox API (ANY.RUN or Hybrid Analysis), waits for results, and returns JSON: {"verdict": "MALICIOUS" or "CLEAN", "score": 0-100, "note": "reason", "details": {"behaviors": [...]}}
   - GET /health — Returns {"status": "healthy", "service": "dynamic-analysis"}
   - Runs on port 8004
   - This service should use cloud sandbox APIs (ANY.RUN, Hybrid Analysis, or VirusTotal) instead of running a local VM. Store the API key in an environment variable.

2. `Dockerfile` — Based on python:3.13-slim, installs requirements.txt, copies everything, exposes 8004, runs api_server.py.

3. `requirements.txt` — All Python dependencies including fastapi, uvicorn, python-multipart, requests, plus the sandbox API client library.

Important rules:
- The API response format MUST match exactly: {"verdict", "score", "note", "details"}
- The /scan endpoint receives a binary file as a multipart upload (parameter name: "file") — NOT a .eml
- Use tempfile for safe file handling, clean up after scanning
- API keys must come from environment variables (os.environ), never hardcoded
- The orchestrator will call my service at http://dynamic-analysis:8004/scan
- Handle sandbox API timeouts gracefully (sandbox analysis can take 1-5 minutes)
```

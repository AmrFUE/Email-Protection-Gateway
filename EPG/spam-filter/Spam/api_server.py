"""
Spam Filter Microservice — Email Protection Gateway (EPG)
Member 1: Spam Filter on port 8001
"""

import os, email, re, tempfile, logging
from contextlib import asynccontextmanager
from datetime import datetime
from email.utils import parsedate_to_datetime

import pandas as pd
import joblib
import spf
import dkim
import dns.resolver
import requests as http_requests
import nltk

from fastapi import FastAPI, UploadFile, File, HTTPException
import uvicorn

from body_spam_detector import extract_email_body, predict_body_spam

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("spam-filter")

nltk.download("punkt", quiet=True)
nltk.download("punkt_tab", quiet=True)
nltk.download("stopwords", quiet=True)
nltk.download("wordnet", quiet=True)

from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

stop_words = set(stopwords.words("english"))
lemmatizer = WordNetLemmatizer()

header_model = None
body_model = None

VT_API_KEY = os.environ.get(
    "VT_API_KEY",
    "92cb93aac4f76c34acbe4b38b2b8610b5ee5533782796dbaa5ef3392e4c5e499",
)


# ── Text Preprocessing ──

def preprocess_text(text):
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(r'http\S+|www\S+', '', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    tokens = word_tokenize(text)
    tokens = [w for w in tokens if w not in stop_words]
    tokens = [lemmatizer.lemmatize(w) for w in tokens]
    return " ".join(tokens)


# ── Email Parsing Helpers ──

def load_email(path):
    with open(path, "rb") as f:
        raw_email = f.read()
    return email.message_from_bytes(raw_email), raw_email


def extract_domain(address):
    if address and "@" in address:
        return address.split("@")[-1].strip(">")
    return None


def received_count(msg):
    rec = msg.get_all("Received")
    return len(rec) if rec else 0


def smtp_relay_count(msg):
    received = msg.get_all("Received")
    if not received:
        return 0
    internal = re.compile(
        r"(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|"
        r"192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)"
    )
    return sum(1 for hop in received if not internal.search(hop))


def missing_headers(msg):
    required = ["From", "To", "Subject", "Message-ID", "Date"]
    return sum(1 for h in required if msg.get(h) is None)


def fake_from(msg):
    from_dom = extract_domain(msg.get("From"))
    ret_path = msg.get("Return-Path")
    if not ret_path or ret_path.strip() in ("", "<>"):
        return 0
    ret_dom = extract_domain(ret_path)
    if not from_dom or not ret_dom:
        return 0
    return int(from_dom.lower() != ret_dom.lower())


def message_id_mismatch(msg):
    msgid = msg.get("Message-ID")
    from_dom = extract_domain(msg.get("From"))
    if msgid and "@" in msgid:
        msg_dom = msgid.split("@")[-1].strip(">")
        if from_dom:
            return int(msg_dom.lower() != from_dom.lower())
    return 1


def timestamp_anomaly(msg):
    date = msg.get("Date")
    try:
        email_time = parsedate_to_datetime(date)
        if email_time > datetime.now(email_time.tzinfo):
            return 1
    except (TypeError, ValueError, OverflowError):
        return 1
    return 0


def extract_sender_ip(msg):
    received = msg.get_all("Received")
    if not received:
        return None
    for hop in reversed(received):
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", hop)
        for ip in ips:
            if not (ip.startswith("127.") or ip.startswith("10.") or
                    ip.startswith("192.168.") or
                    re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)):
                return ip
    last = received[-1]
    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", last)
    return ips[0] if ips else None


# ── Authentication Checks ──

def check_spf(ip, sender, helo):
    try:
        if not ip or not sender:
            return "unknown"
        result, _ = spf.check2(i=ip, s=sender, h=helo)
        if result in ("pass", "fail"):
            return result
        return "unknown"
    except Exception:
        return "unknown"


def check_dkim(msg, raw_email):
    try:
        if not msg.get("DKIM-Signature"):
            return "unknown"
        return "pass" if dkim.verify(raw_email) else "fail"
    except Exception:
        return "unknown"


def get_dmarc_policy(domain):
    try:
        answers = dns.resolver.resolve("_dmarc." + domain, "TXT")
        record = str(answers[0])
        if "p=reject" in record:
            return "reject", record
        elif "p=quarantine" in record:
            return "quarantine", record
        return "none", record
    except Exception:
        return None, None


def is_aligned(d1, d2, mode="relaxed"):
    if not d1 or not d2:
        return False
    if mode == "strict":
        return d1.lower() == d2.lower()
    return d1.lower().split(".")[-2:] == d2.lower().split(".")[-2:]


def extract_dkim_domain(raw_email):
    try:
        match = re.search(r"d=([^;\s]+)", raw_email.decode(errors="ignore"))
        return match.group(1).strip() if match else None
    except Exception:
        return None


def check_dmarc(from_domain, spf_domain, dkim_domain, spf_result, dkim_result):
    try:
        policy, _ = get_dmarc_policy(from_domain)
        if not policy:
            return "unknown"
        if spf_result == "unknown" and dkim_result == "unknown":
            return "unknown"
        if ((spf_result == "pass" and is_aligned(from_domain, spf_domain)) or
                (dkim_result == "pass" and is_aligned(from_domain, dkim_domain))):
            return "pass"
        if spf_result == "fail" or dkim_result == "fail":
            return "fail"
        return "unknown"
    except Exception:
        return "unknown"


# ── Reputation Checks (VirusTotal) ──

def sender_domain_reputation(domain):
    try:
        if not domain:
            return -1
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = http_requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=10)
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        s = stats["malicious"] + stats["suspicious"]
        return 50 if s == 0 else max(20, 80 - s * 15)
    except Exception:
        return -1


def ip_reputation_score(ip):
    try:
        if not ip:
            return -1
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        r = http_requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=10)
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        s = stats["malicious"] + stats["suspicious"]
        return 50 if s == 0 else max(20, 80 - s * 15)
    except Exception:
        return -1


def received_chain_anomaly(msg):
    received = msg.get_all("Received")
    if not received:
        return 1
    if len(received) > 6:
        return 1
    private_ip = re.compile(
        r"(^|\D)(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
        r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(\D|$)"
    )
    if private_ip.search(received[-1]):
        return 1
    return 0


# ── Feature Extraction ──

def extract_features(msg, raw_email):
    sender = msg.get("From")
    domain = extract_domain(sender)
    ip = extract_sender_ip(msg)

    spf_result = check_spf(ip, sender, domain)
    dkim_result = check_dkim(msg, raw_email)
    spf_domain = extract_domain(msg.get("Return-Path")) or domain
    dkim_domain = extract_dkim_domain(raw_email)
    dmarc_result = check_dmarc(domain, spf_domain, dkim_domain, spf_result, dkim_result)

    domain_rep = sender_domain_reputation(domain)
    ip_rep = ip_reputation_score(ip)

    data = {
        "Received_Count": [received_count(msg)],
        "Missing_Headers_Count": [missing_headers(msg)],
        "SMTP_Relay_Count": [smtp_relay_count(msg)],
        "Sender_Domain_Reputation": [domain_rep],
        "IP_Reputation_Score": [ip_rep],
        "Fake_From": [fake_from(msg)],
        "Broken_Message_ID": [message_id_mismatch(msg)],
        "Received_Chain_Anomaly": [received_chain_anomaly(msg)],
        "Impossible_Timestamps": [timestamp_anomaly(msg)],
        "SPF_Result": [spf_result],
        "DKIM_Result": [dkim_result],
        "DMARC_Result": [dmarc_result],
    }
    return pd.DataFrame(data)


# ── Scoring & Decision Engine ──

def compute_verdict(msg, raw_email):
    features = extract_features(msg, raw_email)
    ham_prob, spam_prob = header_model.predict_proba(features)[0]
    ham_prob = float(ham_prob)
    spam_prob = float(spam_prob)
    logger.info(f"Header model — ham: {ham_prob:.4f}, spam: {spam_prob:.4f}")

    email_body = extract_email_body(msg)
    body_ham_prob, body_spam_prob = predict_body_spam(email_body, body_model)
    body_ham_prob = float(body_ham_prob)
    body_spam_prob = float(body_spam_prob)
    logger.info(f"Body model — ham: {body_ham_prob:.4f}, spam: {body_spam_prob:.4f}")

    spf_result = str(features["SPF_Result"][0])
    dkim_result = str(features["DKIM_Result"][0])
    dmarc_result = str(features["DMARC_Result"][0])
    ip_rep = int(features["IP_Reputation_Score"][0])
    domain_rep = int(features["Sender_Domain_Reputation"][0])

    score = 0
    breakdown = []

    # 1. ML Header Model (0-4 pts)
    if spam_prob > 0.9:
        score += 4; breakdown.append(("ML header (>90% spam)", 4))
    elif spam_prob > 0.75:
        score += 3; breakdown.append(("ML header (>75% spam)", 3))
    elif spam_prob > 0.6:
        score += 2; breakdown.append(("ML header (>60% spam)", 2))
    elif spam_prob > 0.5:
        score += 1; breakdown.append(("ML header (>50% spam)", 1))
    elif spam_prob < 0.2:
        score -= 1; breakdown.append(("ML header (<20% spam)", -1))

    # 2. Auth checks
    for name, val in [("SPF", spf_result), ("DKIM", dkim_result), ("DMARC", dmarc_result)]:
        if val == "fail":
            score += 2; breakdown.append((f"{name} fail", 2))
        elif val == "pass":
            score -= 1; breakdown.append((f"{name} pass", -1))

    # 3. IP reputation
    if ip_rep != -1:
        if ip_rep < 30:
            score += 3; breakdown.append(("IP reputation bad", 3))
        elif ip_rep < 50:
            score += 1; breakdown.append(("IP reputation neutral", 1))
        else:
            score -= 1; breakdown.append(("IP reputation clean", -1))

    # 4. Domain reputation
    if domain_rep != -1:
        if domain_rep < 30:
            score += 3; breakdown.append(("Domain reputation bad", 3))
        elif domain_rep < 50:
            score += 1; breakdown.append(("Domain reputation neutral", 1))
        else:
            score -= 1; breakdown.append(("Domain reputation clean", -1))

    # 5. Combo bonus
    if ((spf_result == "fail" or dkim_result == "fail") and
            ((ip_rep != -1 and ip_rep < 40) or (domain_rep != -1 and domain_rep < 40))):
        score += 2; breakdown.append(("Auth fail + bad reputation combo", 2))

    # 6. ML Body (0-5 pts)
    if body_spam_prob > 0.9:
        score += 5; breakdown.append(("ML body (>90% spam)", 5))
    elif body_spam_prob > 0.75:
        score += 3; breakdown.append(("ML body (>75% spam)", 3))
    elif body_spam_prob > 0.6:
        score += 2; breakdown.append(("ML body (>60% spam)", 2))
    elif body_spam_prob > 0.5:
        score += 1; breakdown.append(("ML body (>50% spam)", 1))
    elif body_spam_prob < 0.2:
        score -= 1; breakdown.append(("ML body (<20% spam)", -1))

    # 7. Agreement bonus
    if spam_prob > 0.7 and body_spam_prob > 0.7:
        score += 2; breakdown.append(("Header + Body both flag spam", 2))

    # ── Final Decision ──
    if spam_prob >= 0.98 and body_spam_prob >= 0.90:
        verdict = "SPAM"
        reason = "Both ML models extremely confident (header>=98%, body>=90%)"
    elif body_spam_prob >= 0.95 and spam_prob >= 0.90:
        verdict = "SPAM"
        reason = f"Both models agree on spam (body={body_spam_prob:.2%}, header={spam_prob:.2%})"
    elif score >= 8:
        verdict = "SPAM"
        reason = f"High combined score ({score} >= 8)"
    elif score >= 4:
        verdict = "SPAM"
        reason = f"Moderate-high combined score ({score} >= 4)"
    elif score <= 0 and spam_prob < 0.3 and body_spam_prob < 0.3:
        verdict = "HAM"
        reason = f"Low score ({score}) + low spam probabilities"
    elif score <= 2:
        verdict = "HAM"
        reason = f"Low combined score ({score} <= 2)"
    else:
        verdict = "SPAM"
        reason = "Uncertain — flagging as spam for safety"

    # Normalize score to 0-100
    normalized_score = max(0, min(100, round((score + 7) / 34 * 100)))

    details = {
        "header_spam_probability": round(spam_prob, 4),
        "body_spam_probability": round(body_spam_prob, 4),
        "raw_score": score,
        "score_breakdown": [{"factor": f, "points": p} for f, p in breakdown],
        "authentication": {"spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result},
        "reputation": {"ip_score": ip_rep, "domain_score": domain_rep},
        "sender": msg.get("From", "unknown"),
        "subject": msg.get("Subject", ""),
    }

    return verdict, normalized_score, reason, details


# ── FastAPI Application ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    global header_model, body_model
    logger.info("Loading ML models...")
    header_model = joblib.load("spam_model.pkl")
    logger.info("Header model loaded.")
    body_model = joblib.load("body_spam_model.pkl")
    logger.info("Body model loaded.")
    yield
    logger.info("Shutting down spam filter service.")


app = FastAPI(
    title="EPG Spam Filter",
    description="Email Protection Gateway — Spam Filter Microservice",
    version="1.0.0",
    lifespan=lifespan,
)


@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    """Receive a .eml email file, analyze it for spam, return verdict."""
    tmp_path = None
    try:
        content = await file.read()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        logger.info(f"Scanning: {file.filename} ({len(content)} bytes)")
        msg, raw_email = load_email(tmp_path)
        verdict, score, note, details = compute_verdict(msg, raw_email)

        return {"verdict": verdict, "score": score, "note": note, "details": details}

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan error: {type(e).__name__}: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "spam-filter"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)

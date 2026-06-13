import os
import email
import re
import pandas as pd
import joblib
import spf
import dkim
import dns.resolver
import whois
import requests
import nltk
from datetime import datetime
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

from body_spam_detector import extract_email_body, load_body_model, predict_body_spam

from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

stop_words = set(stopwords.words("english"))
lemmatizer = WordNetLemmatizer()


def preprocess_text(text):
    """Clean and normalize text for NLP processing."""
    if not text:
        return ""

    text = text.lower()

    text = re.sub(r'\S+@\S+', '', text)       # remove emails
    text = re.sub(r'http\S+|www\S+', '', text) # remove URLs
    text = re.sub(r'\d+', '', text)            # remove numbers
    text = re.sub(r'[^a-zA-Z\s]', '', text)    # keep only letters and spaces

    tokens = word_tokenize(text)
    tokens = [w for w in tokens if w not in stop_words]
    tokens = [lemmatizer.lemmatize(w) for w in tokens]

    return " ".join(tokens)


def load_email(path):
    """Load an email file and return parsed message + raw bytes."""
    with open(path, "rb") as f:
        raw_email = f.read()

    msg = email.message_from_bytes(raw_email)
    return msg, raw_email


def extract_domain(address):
    """Extract domain from an email address string."""
    if address and "@" in address:
        return address.split("@")[-1].strip(">")
    return None


def received_count(msg):
    """Count the number of Received headers."""
    rec = msg.get_all("Received")
    if rec:
        return len(rec)
    return 0


def smtp_relay_count(msg):
    """
    Count only external SMTP relays in the Received chain.
    Excludes hops that are localhost or private/internal IPs,
    since those are internal MTA handoffs, not real relays.
    """
    received = msg.get_all("Received")
    if not received:
        return 0

    internal_pattern = re.compile(
        r"(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|"
        r"192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)"
    )

    external_hops = 0
    for hop in received:
        if not internal_pattern.search(hop):
            external_hops += 1

    return external_hops


def missing_headers(msg):
    """Count the number of missing essential headers."""
    required = ["From", "To", "Subject", "Message-ID", "Date"]
    missing = 0
    for h in required:
        if msg.get(h) is None:
            missing += 1
    return missing


def fake_from(msg):
    """
    Check if From domain mismatches Return-Path domain.
    Returns 0 (not fake) if Return-Path is missing — absence of
    Return-Path is common in legitimate mailing list emails.
    """
    from_dom = extract_domain(msg.get("From"))
    ret_path = msg.get("Return-Path")

    # If Return-Path is missing or empty, we can't determine mismatch
    if not ret_path or ret_path.strip() in ("", "<>"):
        return 0

    ret_dom = extract_domain(ret_path)

    # If either domain couldn't be extracted, don't flag
    if not from_dom or not ret_dom:
        return 0

    return int(from_dom.lower() != ret_dom.lower())


def message_id_mismatch(msg):
    """Check if Message-ID domain mismatches From domain."""
    msgid = msg.get("Message-ID")
    from_dom = extract_domain(msg.get("From"))

    if msgid and "@" in msgid:
        msg_dom = msgid.split("@")[-1].strip(">")
        if from_dom:
            return int(msg_dom.lower() != from_dom.lower())
    return 1


def timestamp_anomaly(msg):
    """Check if the email Date header is in the future (impossible timestamp)."""
    date = msg.get("Date")

    try:
        email_time = parsedate_to_datetime(date)
        if email_time > datetime.now(email_time.tzinfo):
            return 1
    except (TypeError, ValueError, OverflowError):
        return 1

    return 0


def extract_sender_ip(msg):
    """
    Extract the originating sender's IP from the Received chain.
    Received headers are prepended (newest first), so the LAST header
    in the list is the first hop — the one closest to the original sender.
    """
    received = msg.get_all("Received")

    if not received:
        return None

    # Walk from the last (oldest/first hop) upward to find the first
    # public IP — this is most likely the originating sender's IP
    for hop in reversed(received):
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", hop)
        for ip in ips:
            # Skip private/loopback IPs
            if not (ip.startswith("127.") or ip.startswith("10.") or
                    ip.startswith("192.168.") or
                    re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)):
                return ip

    # Fallback: return any IP from the last received header
    last = received[-1]
    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", last)
    if ips:
        return ips[0]

    return None


def check_spf(ip, sender, helo):
    """Check SPF record for the sender. Returns 'pass', 'fail', or 'unknown'."""
    try:
        if not ip or not sender:
            print("SPF: missing IP or sender -> using 'unknown' -> scoring contribution = 0")
            return "unknown"

        result, explanation = spf.check2(i=ip, s=sender, h=helo)

        if result == "pass":
            print("SPF: pass")
            return "pass"

        if result == "fail":
            print("SPF: fail")
            return "fail"

        print(f"SPF: {result} -> using 'unknown' -> scoring contribution = 0")
        return "unknown"

    except (spf.TempError, spf.PermError, dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
        print(f"SPF: lookup error ({type(e).__name__}) -> using 'unknown'")
        return "unknown"
    except Exception as e:
        print(f"SPF: unexpected error ({type(e).__name__}: {e}) -> using 'unknown'")
        return "unknown"


def check_dkim(msg, raw_email):
    """Check DKIM signature validity. Returns 'pass', 'fail', or 'unknown'."""
    try:
        dkim_header = msg.get("DKIM-Signature")

        if not dkim_header:
            print("DKIM: no DKIM-Signature header -> using 'unknown' -> scoring contribution = 0")
            return "unknown"

        if dkim.verify(raw_email):
            print("DKIM: pass")
            return "pass"

        print("DKIM: signature exists but verification failed -> fail")
        return "fail"

    except (dkim.DKIMException, dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
        print(f"DKIM: verification error ({type(e).__name__}) -> using 'unknown'")
        return "unknown"
    except Exception as e:
        print(f"DKIM: unexpected error ({type(e).__name__}: {e}) -> using 'unknown'")
        return "unknown"


def get_dmarc_policy(domain):
    """Extract DMARC policy from DNS TXT record for the given domain."""
    try:
        answers = dns.resolver.resolve("_dmarc." + domain, "TXT")
        record = str(answers[0])

        if "p=reject" in record:
            return "reject", record
        elif "p=quarantine" in record:
            return "quarantine", record
        else:
            return "none", record

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
        print(f"DMARC DNS: {type(e).__name__} for _dmarc.{domain}")
        return None, None
    except Exception as e:
        print(f"DMARC DNS: unexpected error ({type(e).__name__}: {e})")
        return None, None


def is_aligned(domain1, domain2, mode="relaxed"):
    """
    Check if two domains are aligned.
    strict = exact match, relaxed = same organizational domain.
    """
    if not domain1 or not domain2:
        return False

    if mode == "strict":
        return domain1.lower() == domain2.lower()

    # relaxed → same root domain
    return domain1.lower().split(".")[-2:] == domain2.lower().split(".")[-2:]


def extract_dkim_domain(raw_email):
    """Extract DKIM domain (d=) from raw email headers."""
    try:
        match = re.search(r"d=([^;\s]+)", raw_email.decode(errors="ignore"))
        if match:
            return match.group(1).strip()
    except (UnicodeDecodeError, AttributeError) as e:
        print(f"DKIM domain extraction error: {type(e).__name__}")
    return None


def check_dmarc(from_domain, spf_domain, dkim_domain, spf_result, dkim_result):
    """
    Perform DMARC validation using SPF/DKIM results + domain alignment.
    Returns 'pass', 'fail', or 'unknown'.
    """
    try:
        policy, record = get_dmarc_policy(from_domain)

        if not policy:
            print("DMARC: no record -> unknown")
            return "unknown"

        # If both auth methods are unknown, DMARC can't be judged reliably
        if spf_result == "unknown" and dkim_result == "unknown":
            print(f"DMARC: SPF and DKIM are both unknown (policy={policy}) "
                  f"-> using 'unknown' -> scoring contribution = 0")
            return "unknown"

        spf_aligned = is_aligned(from_domain, spf_domain)
        dkim_aligned = is_aligned(from_domain, dkim_domain)

        if ((spf_result == "pass" and spf_aligned) or
                (dkim_result == "pass" and dkim_aligned)):
            print(f"DMARC: pass (policy={policy})")
            return "pass"

        # Only fail if at least one method was actually evaluated and failed
        if spf_result == "fail" or dkim_result == "fail":
            print(f"DMARC: fail (policy={policy})")
            return "fail"

        print(f"DMARC: not enough evidence (policy={policy}) "
              f"-> using 'unknown' -> scoring contribution = 0")
        return "unknown"

    except Exception as e:
        print(f"DMARC: error ({type(e).__name__}: {e}) -> unknown")
        return "unknown"


# --- Reputation Checks (VirusTotal) ---

VT_API_KEY = os.environ.get("VT_API_KEY",
    "92cb93aac4f76c34acbe4b38b2b8610b5ee5533782796dbaa5ef3392e4c5e499")


def sender_domain_reputation(domain):
    """
    Query VirusTotal for domain reputation.
    Returns a score: 50 = clean, lower = worse. -1 = unknown/error.
    """
    try:
        if not domain:
            return -1

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}

        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        print("VirusTotal Domain stats:", stats)
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        score = malicious + suspicious
        if score == 0:
            return 50  # clean/neutral
        else:
            return max(20, 80 - score * 15)

    except requests.exceptions.Timeout:
        print("VirusTotal Domain: request timed out -> unknown")
        return -1
    except requests.exceptions.HTTPError as e:
        print(f"VirusTotal Domain: HTTP error {e.response.status_code} -> unknown")
        return -1
    except (KeyError, ValueError) as e:
        print(f"VirusTotal Domain: response parse error ({type(e).__name__}) -> unknown")
        return -1
    except Exception as e:
        print(f"VirusTotal Domain: unexpected error ({type(e).__name__}: {e}) -> unknown")
        return -1


def ip_reputation_score(ip):
    """
    Query VirusTotal for IP reputation.
    Returns a score: 50 = clean, lower = worse. -1 = unknown/error.
    """
    try:
        if not ip:
            return -1

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}

        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        print("VirusTotal IP stats:", stats)
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        score = malicious + suspicious
        if score == 0:
            return 50  # clean/neutral known
        else:
            return max(20, 80 - score * 15)

    except requests.exceptions.Timeout:
        print("VirusTotal IP: request timed out -> unknown")
        return -1
    except requests.exceptions.HTTPError as e:
        print(f"VirusTotal IP: HTTP error {e.response.status_code} -> unknown")
        return -1
    except (KeyError, ValueError) as e:
        print(f"VirusTotal IP: response parse error ({type(e).__name__}) -> unknown")
        return -1
    except Exception as e:
        print(f"VirusTotal IP: unexpected error ({type(e).__name__}: {e}) -> unknown")
        return -1


def received_chain_anomaly(msg):
    """
    Detect anomalies in the Received header chain.
    Flags:
      - Missing Received headers entirely
      - Excessive hop count (>6)
      - Private IPs in the ORIGINATING (last/oldest) hop only
        (private IPs in intermediate hops are normal for corporate relays)
    """
    received = msg.get_all("Received")

    if not received:
        return 1

    count = len(received)

    # Too many hops is suspicious
    if count > 6:
        return 1

    # Only check the originating hop (last in the list = first added)
    # for private IPs — private IPs here suggest spoofed or local-only origin
    originating_hop = received[-1]
    private_ip_pattern = re.compile(
        r"(^|\D)(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
        r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(\D|$)"
    )

    if private_ip_pattern.search(originating_hop):
        return 1

    return 0


def extract_features(msg, raw_email):
    """
    Extract all header-based features from an email for spam classification.
    Returns a DataFrame with one row of features.
    """
    subject = msg.get("Subject")
    print("Original Subject:", subject)
    print("Clean Subject:", preprocess_text(subject))

    sender = msg.get("From")
    domain = extract_domain(sender)
    ip = extract_sender_ip(msg)
    helo = domain

    # Authentication checks
    spf_result = check_spf(ip, sender, helo)
    dkim_result = check_dkim(msg, raw_email)

    spf_domain = extract_domain(msg.get("Return-Path")) or domain
    dkim_domain = extract_dkim_domain(raw_email)

    dmarc_result = check_dmarc(domain, spf_domain, dkim_domain, spf_result, dkim_result)

    # Reputation checks
    domain_rep = sender_domain_reputation(domain)
    ip_rep = ip_reputation_score(ip)

    # Structural checks
    chain_anomaly = received_chain_anomaly(msg)

    data = {
        "Received_Count": [received_count(msg)],
        "Missing_Headers_Count": [missing_headers(msg)],
        "SMTP_Relay_Count": [smtp_relay_count(msg)],
        "Sender_Domain_Reputation": [domain_rep],
        "IP_Reputation_Score": [ip_rep],
        "Fake_From": [fake_from(msg)],
        "Broken_Message_ID": [message_id_mismatch(msg)],
        "Received_Chain_Anomaly": [chain_anomaly],
        "Impossible_Timestamps": [timestamp_anomaly(msg)],
        "SPF_Result": [spf_result],
        "DKIM_Result": [dkim_result],
        "DMARC_Result": [dmarc_result]
    }

    return pd.DataFrame(data)


# ──────────────────────────────────────────────────────────────────────
#  MAIN — Scoring & Decision Engine
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    header_model = joblib.load("spam_model.pkl")
    body_model = load_body_model("body_spam_model.pkl")

    msg, raw_email = load_email("incoming_email.eml")

    # ── Header-Based Analysis ──
    features = extract_features(msg, raw_email)

    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    pd.set_option('display.max_colwidth', None)

    print("\n" + "=" * 70)
    print("  EXTRACTED HEADER FEATURES")
    print("=" * 70)
    print(features.to_string(index=False))

    # -- ML Header Prediction --
    ham_prob, spam_prob = header_model.predict_proba(features)[0]

    print(f"\n{'-' * 40}")
    print(f"  ML Header Model Prediction")
    print(f"{'-' * 40}")
    print(f"  Ham probability : {ham_prob * 100:.4f}%")
    print(f"  Spam probability: {spam_prob * 100:.4f}%")

    # ── Body-Based Analysis ──
    email_body = extract_email_body(msg)

    print(f"\n{'-' * 40}")
    print(f"  Email Body Extracted")
    print(f"{'-' * 40}")
    body_preview = email_body[:200].replace('\n', ' ').strip()
    print(f"  Preview: {body_preview}...")
    print(f"  Body length: {len(email_body)} chars")

    body_ham_prob, body_spam_prob = predict_body_spam(email_body, body_model)

    print(f"\n{'-' * 40}")
    print(f"  ML Body Model Prediction")
    print(f"{'-' * 40}")
    print(f"  Ham probability : {body_ham_prob * 100:.4f}%")
    print(f"  Spam probability: {body_spam_prob * 100:.4f}%")

    # -- Extract key feature values --
    spf_result = features["SPF_Result"][0]
    dkim_result = features["DKIM_Result"][0]
    dmarc_result = features["DMARC_Result"][0]
    ip_rep = features["IP_Reputation_Score"][0]
    domain_rep = features["Sender_Domain_Reputation"][0]

    # ==================================================================
    #  SCORING SYSTEM (max ~27 points spam, min ~ -7 points ham)
    # ==================================================================

    score = 0
    score_breakdown = []

    # 1. ML Header Model Score (0 to 4 points)
    if spam_prob > 0.9:
        score += 4
        score_breakdown.append(("ML header (>90% spam)", +4))
    elif spam_prob > 0.75:
        score += 3
        score_breakdown.append(("ML header (>75% spam)", +3))
    elif spam_prob > 0.6:
        score += 2
        score_breakdown.append(("ML header (>60% spam)", +2))
    elif spam_prob > 0.5:
        score += 1
        score_breakdown.append(("ML header (>50% spam)", +1))
    elif spam_prob < 0.2:
        score -= 1
        score_breakdown.append(("ML header (<20% spam - likely ham)", -1))

    # 2. Authentication -- penalties for fail, BONUSES for pass
    if spf_result == "fail":
        score += 2
        score_breakdown.append(("SPF fail", +2))
    elif spf_result == "pass":
        score -= 1
        score_breakdown.append(("SPF pass", -1))

    if dkim_result == "fail":
        score += 2
        score_breakdown.append(("DKIM fail", +2))
    elif dkim_result == "pass":
        score -= 1
        score_breakdown.append(("DKIM pass", -1))

    if dmarc_result == "fail":
        score += 2
        score_breakdown.append(("DMARC fail", +2))
    elif dmarc_result == "pass":
        score -= 1
        score_breakdown.append(("DMARC pass", -1))

    # 3. IP reputation (skip if unknown = -1)
    if ip_rep != -1:
        if ip_rep < 30:
            score += 3
            score_breakdown.append(("IP reputation bad (<30)", +3))
        elif ip_rep < 50:
            score += 1
            score_breakdown.append(("IP reputation neutral (<50)", +1))
        else:
            score -= 1
            score_breakdown.append(("IP reputation clean (>=50)", -1))

    # 4. Domain reputation (skip if unknown = -1)
    if domain_rep != -1:
        if domain_rep < 30:
            score += 3
            score_breakdown.append(("Domain reputation bad (<30)", +3))
        elif domain_rep < 50:
            score += 1
            score_breakdown.append(("Domain reputation neutral (<50)", +1))
        else:
            score -= 1
            score_breakdown.append(("Domain reputation clean (>=50)", -1))

    # 5. Combo bonus: auth fail + bad reputation = extra suspicious
    if ((spf_result == "fail" or dkim_result == "fail") and
            ((ip_rep != -1 and ip_rep < 40) or
             (domain_rep != -1 and domain_rep < 40))):
        score += 2
        score_breakdown.append(("Auth fail + bad reputation combo", +2))

    # 6. ML Body Content Score (0 to 5 points)
    if body_spam_prob > 0.9:
        score += 5
        score_breakdown.append(("ML body (>90% spam)", +5))
    elif body_spam_prob > 0.75:
        score += 3
        score_breakdown.append(("ML body (>75% spam)", +3))
    elif body_spam_prob > 0.6:
        score += 2
        score_breakdown.append(("ML body (>60% spam)", +2))
    elif body_spam_prob > 0.5:
        score += 1
        score_breakdown.append(("ML body (>50% spam)", +1))
    elif body_spam_prob < 0.2:
        score -= 1
        score_breakdown.append(("ML body (<20% spam - likely ham)", -1))

    # 7. Header + Body agreement bonus
    if spam_prob > 0.7 and body_spam_prob > 0.7:
        score += 2
        score_breakdown.append(("Header + Body both flag spam", +2))

    # -- SCORE BREAKDOWN --
    print(f"\n{'-' * 40}")
    print(f"  Score Breakdown")
    print(f"{'-' * 40}")
    for reason, points in score_breakdown:
        sign = "+" if points > 0 else ""
        print(f"  {sign}{points:>3}  {reason}")
    print(f"{'-' * 40}")
    print(f"  TOTAL SCORE: {score}")

    # ==================================================================
    #  FINAL DECISION (three-tier)
    # ==================================================================

    print(f"\n{'=' * 70}")

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
        verdict = "SUSPICIOUS"
        reason = f"Moderate combined score ({score} >= 4)"
    elif score <= 0 and spam_prob < 0.3 and body_spam_prob < 0.3:
        verdict = "LEGIT"
        reason = (f"Low score ({score}) + low header spam ({spam_prob:.2%}) "
                  f"+ low body spam ({body_spam_prob:.2%})")
    elif score <= 2:
        verdict = "LEGIT"
        reason = f"Low combined score ({score} <= 2)"
    else:
        verdict = "SUSPICIOUS"
        reason = "Unable to determine with high confidence"

    label_map = {"SPAM": "[!!!]", "SUSPICIOUS": "[?]", "LEGIT": "[OK]"}

    print(f"  {label_map[verdict]}  VERDICT: {verdict}")
    print(f"  Reason: {reason}")
    print("=" * 70)

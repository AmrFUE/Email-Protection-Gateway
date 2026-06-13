import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "src" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

DATASET_CSV = BASE_DIR / "dataset" / "Nazario_5.csv"
DOMAIN_EXCEL = BASE_DIR / "domain" / "final_domain.xlsx"

# Brand list presets for lookalike / typosquatting checking
LEGITIMATE_BRANDS = [
    "microsoft.com",
    "paypal.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "netflix.com",
    "linkedin.com",
    "yahoo.com",
    "dropbox.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "outlook.com",
    "gmail.com",
    "microsoftonline.com",
    "adobe.com",
    "zoom.us",
    "docuSign.com",
    "salesforce.com"
]

# TLD Phishing Risk Ratings (0.0 to 1.0)
HIGH_RISK_TLDS = {
    "zip": 0.95,
    "mov": 0.90,
    "fit": 0.85,
    "top": 0.85,
    "tk": 0.80,
    "ml": 0.80,
    "ga": 0.80,
    "cf": 0.80,
    "gq": 0.80,
    "download": 0.75,
    "click": 0.75,
    "support": 0.70,
    "work": 0.70,
    "party": 0.75,
    "science": 0.70,
    "icu": 0.70,
    "xyz": 0.65,
    "bid": 0.65,
    "date": 0.60
}

# Suspicious User-Agents or X-Mailers
SUSPICIOUS_MAILERS = [
    "php",
    "python",
    "kali",
    "sqlmap",
    "curl",
    "wget",
    "nodemailer",
    "smtp",
    "perl",
    "supermailer",
    "sendgrid-nodejs",
    "roundcube",
    "hacker",
    "hydra"
]

# Keyword presets for backup heuristic scoring & NLP feature tagging
URGENCY_KEYWORDS = [
    "urgent", "immediate", "suspend", "expire", "terminate", "restrict", 
    "action required", "24 hours", "48 hours", "unauthorized", "critical", 
    "final notice", "deadline", "important notice", "locked", "blocked"
]

CREDENTIAL_KEYWORDS = [
    "login", "verify", "update", "password", "credential", "sign in", 
    "account details", "confirm", "validation", "reset password", 
    "security upgrade", "verify identity", "sign-in", "authorization code"
]

BEC_KEYWORDS = [
    "wire transfer", "payment", "invoice", "gift card", "executive", "ceo", 
    "urgent request", "financial", "direct deposit", "confidential request", 
    "acquisitions", "quick task", "are you at your desk", "transfer funds"
]

# Scoring weights — technical indicators dominate, NLP is supportive only
WEIGHTS = {
    "header_score": 0.35,
    "url_score": 0.45,
    "nlp_score": 0.20
}

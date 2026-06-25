# Email Protection Gateway (EPG)

> A four-layer email security pipeline built for enterprise environments. Deployed on Azure and integrated with a real mail server.

---

## What It Does

EPG intercepts every inbound email before delivery and passes it through four sequential analysis stages. Each stage runs as an independent microservice. A central orchestrator collects all verdicts and issues a final decision: **CLEAN**, **QUARANTINE**, or **BLOCK**.

```
Inbound Email (SMTP :25 / :587)
        │
        ▼
  ┌─────────────┐
  │  EPG Bridge │  ← Intercepts mail before delivery
  └──────┬──────┘
         │
         ▼
  ┌─────────────────────────────────────────┐
  │            Orchestrator                 │
  │                                         │
  │  Stage 1: Static Malware Scanner :8003  │
  │  Stage 2: Dynamic Analysis       :8004  │
  │  Stage 3: Phishing Filter        :8002  │
  │  Stage 4: Spam Filter            :8001  │
  └──────────────────┬──────────────────────┘
                     │
                     ▼
            Mail Server (poste.io)
            Webmail: jawabi.app
```

---

## Pipeline Stages

### Stage 1 — Static Malware Scanner
Four-sub-layer static analysis pipeline for email attachments.

**Layer 1 — Threat Intelligence**
- Hash lookup against MalwareBazaar, ThreatFox, and AlienVault OTX
- Fuzzy hash matching (ssdeep) for near-duplicate detection
- YARA scanning with 200+ rules covering APT groups, ransomware families, RATs, malicious macros, POS malware, and toolkits
- SQLite cache for repeated lookups

**Layer 2 — String & IOC Extraction**
- Extracts embedded IPs, URLs, API calls, registry keys, and suspicious strings
- Checks extracted URLs against URLhaus live threat feed
- Heuristic scoring on extracted strings

**Layer 3 — ML Models**
- **PDF files** → Random Forest (32 features, trained on CIC-Evasive-PDFMal2022)
- **Office files** → XGBoost (40 features, OLE2/macro analysis)
- **PE executables** → EMBER-based feature set with entropy analysis
- SHAP explanations for every ML prediction

**Layer 4 — Archive Handler**
- Recursive scanning of ZIP/RAR/7z archives up to configurable depth
- Per-file verdicts rolled into an overall archive verdict

Supported file types: PDF, DOCX/XLSX/PPTX, EXE/DLL, ZIP/RAR/7z, RTF

### Stage 2 — Dynamic Analysis
URL-focused dynamic pipeline for live phishing site detection.

- Headless browser rendering with screenshot capture
- Redirect chain graphing and domain intelligence
- Defacement detection
- Reputation cross-referencing

### Stage 3 — Phishing Filter
Detects phishing emails using three sub-engines fused by a hybrid aggregator.

- **Header Analyzer** — checks SPF/DKIM/DMARC, display name spoofing, Reply-To mismatches, X-Mailer anomalies
- **URL Analyzer** — detects domain squatting, typosquatting, URL obfuscation, and brand impersonation
- **NLP Analyzer** — semantic analysis of email body for urgency, fear, credential-harvesting patterns
- Outputs explainable AI reasons for every detection

### Stage 4 — Spam Filter
Analyzes email headers and body content using two ML models.

- Extracts 12 header features: SPF/DKIM/DMARC results, IP reputation, domain reputation, relay count, timestamp anomalies, missing headers, and more
- Runs a separate NLP body model on email body text (NLTK preprocessing + lemmatization)
- Combines both model scores in a weighted scoring system (max ~27 points)
- Three-tier verdict: **SPAM**, **SUSPICIOUS**, **LEGIT**

---

## Dashboard Screenshots

<p align="center">
  <img src="screenshots/Screenshot%202026-06-25%20154553.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154604.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154614.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154620.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154628.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154638.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154717.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154724.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154732.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154740.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154749.png" width="48%">
  <img src="screenshots/Screenshot%202026-06-25%20154800.png" width="48%">
</p>

---

## Architecture

> [!TIP]
> See [SYSTEM_MAP.md](SYSTEM_MAP.md) for a visual diagram of the EPG layers.

```
epg/
├── EPG/
│   ├── orchestrator/         # Routes email through all stages
│   ├── spam-filter/          # Stage 1 — header + body ML
│   ├── phishing-filter/      # Stage 2 — header/URL/NLP analysis
│   ├── malware-scanner/      # Stage 3 — static attachment analysis
│   │   ├── engines/          # Archive handler, string extractor, threat intel
│   │   ├── features/         # Feature extractors (PDF, Office, PE)
│   │   ├── ml/               # ML model loader and detector
│   │   ├── yara_rules/       # 200+ YARA rules
│   │   └── PKL Files/        # Trained models (PDF, Office, PE)
│   ├── dynamic-analysis/     # Stage 4 — URL dynamic analysis
│   └── shared/               # Shared EML parser
├── dashboard/                # Web dashboard (admin UI)
├── mailu/
│   ├── epg-bridge/           # SMTP intercept gateway
│   └── data/                 # Mail server data (SSL, domains, config)
└── docker-compose.yml        # Full stack orchestration
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Orchestrator | Python, Redis |
| Spam Filter | scikit-learn, NLTK, pyspf, dkimpy |
| Phishing Filter | scikit-learn, openpyxl |
| Malware Scanner | scikit-learn, XGBoost, YARA-Python, pefile, ssdeep |
| Dynamic Analysis | Playwright, NetworkX |
| Mail Server | poste.io (SMTP/IMAP/POP3) |
| SMTP Bridge | Python asyncio SMTP |
| Dashboard | Flask, Redis, PostgreSQL |
| Deployment | Azure VM, Docker Compose |
| Database | SQLite (threat cache), PostgreSQL (dashboard) |
| Queue | Redis |

---

## Deployment

### Requirements
- Docker and Docker Compose
- Azure VM (or any Linux host) with ports 25, 80, 443, 587, 8080 open

### Quick Start

```bash
git clone https://github.com/AmrFUE/Email-Protection-Gateway.git
cd Email-Protection-Gateway
docker compose up --build -d
```

### Services

| Service | URL / Port | Credentials |
|---|---|---|
| Admin Dashboard | http://localhost:8080 | admin / admin |
| Webmail (poste.io) | http://jawabi.app | admin@jawabi.app / admin123 |
| Spam Filter API | :8001 | — |
| Phishing Filter API | :8002 | — |
| Malware Scanner API | :8003 | — |
| SMTP (EPG Bridge) | :25, :587 | — |
| IMAP | :143, :993 | — |

### Environment Variables

Copy `.env.example` to `.env` in each service directory before running:

```bash
cp EPG/malware-scanner/.env.example EPG/malware-scanner/.env
```

Key variables for the malware scanner:

```env
OTX_API_KEY=your_alienvault_otx_key
MALWAREBAZAAR_API_KEY=your_key
PORT=8003
```

---

## Running the Malware Scanner Standalone

```bash
cd EPG/malware-scanner

# Scan a single file
python unified_scanner.py sample.pdf

# Scan a directory recursively
python unified_scanner.py --dir /path/to/attachments

# JSON output for pipeline integration
python unified_scanner.py sample.exe --output json
```

### Sample Output

```
================================================================================
 FINAL VERDICT: MALICIOUS  |  Confidence: 97.3%
 Method: ML + YARA Signature
================================================================================
[1/4] Threat Intelligence   → medium risk (score: 45/100)
[2/4] String & IOC          → 3 suspicious URLs, 2 API hits
[3/4] ML Analysis (PDF)     → Malicious (97.3%)
[4/4] Fusion Verdict        → MALICIOUS

Top SHAP drivers:
  [!] High entropy stream detected (7.82)
  [!] Embedded JavaScript with eval()
  [!] Suspicious /OpenAction trigger
```

---

## Running the Phishing Filter Standalone

```bash
cd EPG/phishing-filter/phishing-filter-service

# Scan an .eml file
python run_pipeline.py --file sample.eml

# JSON output
python run_pipeline.py --file sample.eml --json-out

# Demo mode (runs built-in mock phishing email)
python run_pipeline.py
```

---

## YARA Rules Coverage

The malware scanner ships with 200+ YARA rules covering:

- APT groups (APT1, APT10, APT29, Equation Group, FancyBear, Sofacy, Turla, etc.)
- Ransomware families (WannaCry, Petya, Locky, Cerber, REvil, BadRabbit, etc.)
- RATs (NjRAT, DarkComet, AsyncRAT, NanoCore, Meterpreter, etc.)
- Malware (Emotet, TrickBot, Mirai, ZeuS, AgentTesla, IcedID, etc.)
- Malicious Office macros and DDE exploits
- POS malware and banking trojans
- Red team tools and credential dumpers

---

## ML Models

| Model | File Type | Algorithm | Features | Dataset |
|---|---|---|---|---|
| model_pdf.pkl | PDF | Random Forest | 32 | CIC-Evasive-PDFMal2022 |
| model_office.pkl | DOCX/XLSX/PPTX | XGBoost | 40 | Custom OLE2 dataset |
| model_pe.pkl | EXE/DLL | EMBER features | EMBER-based | EMBER dataset |

> **Note:** `extract_features.py` and the trained `.pkl` models are tightly coupled. Never add new features to `extract_features.py` without rebuilding the full dataset and retraining all models.

---

## Team

Final year graduation project — Faculty of Computers and Information Technology, Future University in Egypt (FUE), 2026.

| Stage | Component |
|---|---|
| Stage 1 | Static Malware Scanner |
| Stage 2 | Dynamic URL Analysis |
| Stage 3 | Phishing Filter |
| Stage 4 | Spam Filter |

---

## License

Academic project. Not licensed for production use without review.

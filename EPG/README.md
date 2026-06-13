# Email Protection Gateway (EPG)

Multi-stage email security pipeline that intercepts emails via SMTP and scans them through Spam, Phishing, Static Malware, and Dynamic Analysis before delivery.

## Architecture

```
Internet → [Port 25] → Postfix + Milter → Spam → Phishing → Malware → Dynamic → Mail Server
                                                                ↓
                                                          Quarantine + Admin Dashboard
```

## Quick Start

```bash
# 1. Clone all team projects into their directories
# 2. Configure .env
cp .env.example .env

# 3. Build and run
docker-compose up --build
```

## Project Structure

```
EPG/
├── docker-compose.yml       # Orchestrates all services
├── .env.example             # Template for API keys
├── shared/                  # Shared utilities
│   ├── eml_parser.py        # EML file parsing
│   └── config.py            # Configuration loader
├── orchestrator/            # SMTP milter + email routing
├── malware-scanner/         # Static malware API (Member 3)
├── spam-filter/             # Spam detection API (Member 1)
├── phishing-filter/         # Phishing detection API (Member 2)
├── dynamic-analysis/        # Sandbox API (Member 4)
└── dashboard/               # Admin panel (shared)
```

## Team

| Member | Module | Port |
|--------|--------|------|
| 1 | Spam Filter | 8001 |
| 2 | Phishing Filter | 8002 |
| 3 | Static Malware Scanner | 8003 |
| 4 | Dynamic Analysis | 8004 |

<!-- CHECKPOINT id="ckpt_moeratz3_2kzu44" time="2026-04-25T19:52:47.679Z" note="auto" fixes=0 questions=0 highlights=0 sections="" -->

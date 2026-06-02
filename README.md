# SentinelOSINT — IOC Enrichment & Triage

**LLM-assisted indicator of compromise enrichment across 10 concurrent intelligence sources**

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React-61DAFB)](https://react.dev)
[![Claude](https://img.shields.io/badge/LLM-Anthropic%20Claude-orange)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Overview

SentinelOSINT is a full-stack IOC enrichment pipeline. Submit an IP address, domain, file hash, or URL and it fans out to ten threat intelligence sources concurrently, then passes the aggregated results to Claude to produce a structured triage assessment — verdict, confidence, MITRE ATT&CK mappings, recommended actions, and TLP classification.

This project exists in two versions:

| Version | Description | Entry Point |
|---|---|---|
| **v1 — Notebook** | Jupyter-based prototype. Includes a live prompt injection demonstration and mitigation analysis. | `notebook/osint_report.ipynb` |
| **v2 — Full Stack** | Production-grade FastAPI backend + React frontend. Rebuilt as a focused IOC triage tool. | `backend/` + `frontend/` |

---

## v2 — Full Stack

### Data Sources

The backend fans out to all sources concurrently via `asyncio.gather`. Sources that don't apply to the input type return `status: "not_applicable"` and are excluded from the LLM context automatically.

| Source | Covers | Key signals |
|---|---|---|
| **WHOIS** | Domain, IP | Registrar, creation date, nameservers, registrant |
| **AlienVault OTX** | IP, Domain, URL, Hash | Pulse count, malware families, threat actors |
| **GreyNoise** | IP only | Mass-scanner classification, RIOT benign-service list |
| **AbuseIPDB** | IP only | Abuse confidence score, 365-day report count |
| **Shodan** | IP only | Open ports, service banners, CVEs |
| **MalwareBazaar** | MD5, SHA1, SHA256 | Malware signature, file type, tags |
| **URLhaus** | URL, Domain | Active/offline malicious URL count, tags |
| **CIRCL Passive DNS** | IP, Domain | Historical DNS resolutions (newline-delimited JSON) |
| **VirusTotal Passive DNS** | IP, Domain | Resolutions endpoint; falls back to communicating/referrer files |
| **GitHub** | All | Repository search with proxy-list relevance filtering |
| **ThreatFox** | IP, Domain | IOC database entries, confidence level, threat type |

### Input Type Detection

The backend auto-detects input type before routing:

| Type | Detection rule |
|---|---|
| `ip` | Four dot-separated numeric octets |
| `url` | Starts with `http://` or `https://` |
| `md5` | 32 hex characters |
| `sha1` | 40 hex characters |
| `sha256` | 64 hex characters |
| `email` | Contains `@` with a dot after it |
| `domain` | Contains a dot, not an IP |

### LLM Triage Report

After all sources resolve, Claude synthesizes a structured JSON assessment:

```json
{
  "verdict": "malicious",
  "confidence": "high",
  "summary": "Plain English summary for non-technical stakeholders",
  "key_findings": ["finding 1", "finding 2"],
  "mitre_techniques": [
    { "technique_id": "T1583.001", "technique_name": "Acquire Infrastructure: Domains", "justification": "..." }
  ],
  "recommended_actions": ["Block at perimeter firewall", "Search SIEM for last 90 days"],
  "iocs_extracted": ["associated IOCs found in source data"],
  "tlp": "AMBER"
}
```

The system prompt encodes source reliability weighting, interpretation rules per source, MITRE mapping guidance, and TLP assignment criteria.

---

## Run Locally

**Backend**
```bash
cd backend
pip install -r requirements.txt
cp ../.env.example .env   # fill in your API keys
python -m uvicorn main:app --reload
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api/*` to the FastAPI backend on port 8000.

---

## API

### Single target
```
GET /analyze?target={ip|domain|hash|url}
```

### Batch (up to 10 concurrent)
```
POST /analyze/batch
Content-Type: application/json

{ "targets": ["1.1.1.1", "evil.com", "abc123..."] }
```

### Response shape
```json
{
  "target": "185.220.101.47",
  "input_type": "ip",
  "whois": { "registrar": "...", "created": "...", ... },
  "otx":        { "source": "otx",        "status": "success", "verdict": "malicious", "confidence": "high",   "summary": "...", "raw": { ... } },
  "greynoise":  { "source": "greynoise",  "status": "success", "verdict": "malicious", "confidence": "high",   "summary": "...", "raw": { ... } },
  "abuseipdb":  { "source": "abuseipdb",  "status": "success", "verdict": "malicious", "confidence": "high",   "summary": "...", "raw": { ... } },
  "shodan":     { "source": "shodan",     "status": "success", "verdict": "suspicious","confidence": "medium", "summary": "...", "raw": { ... } },
  "malwarebazaar":  { "source": "malwarebazaar",  "status": "not_applicable", ... },
  "urlhaus":        { "source": "urlhaus",        "status": "not_applicable", ... },
  "circl_pdns":     { "source": "circl_pdns",     "status": "success", ... },
  "vt_passive_dns": { "source": "vt_passive_dns", "status": "success", ... },
  "github":         { "source": "github",         "status": "success", ... },
  "threatfox":      { "source": "threatfox",      "status": "success", "verdict": "malicious", ... },
  "report": { "verdict": "malicious", "confidence": "high", "summary": "...", ... }
}
```

Each source follows the same schema: `{source, status, verdict, confidence, summary, raw}`. Sources that don't apply to the input type return `status: "not_applicable"`.

---

## Project Structure

```
osint-llm-analyst/
├── backend/
│   ├── main.py                 # FastAPI routes — single + batch /analyze endpoints
│   ├── fetchers.py             # All async source integrations + LLM report generation
│   ├── fetch_threatfox.py      # ThreatFox module (standalone, imports detect_input_type)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Full UI — scan pipeline, tabs, indicators, sources
│   │   └── main.jsx
│   ├── index.html
│   ├── vite.config.js          # Dev proxy: /api/* → localhost:8000
│   └── package.json
├── notebook/
│   └── osint_report.ipynb      # v1 prototype with prompt injection demo
├── modules/                    # v1 notebook helper modules
├── .env.example
├── .gitignore
└── README.md
```

---

## API Keys

Copy `.env.example` to `backend/.env` and fill in your keys. Never commit `.env`.

| Variable | Source | Required | Notes |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | **Yes** | Report generation |
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) | **Yes** | Passive DNS; free tier 500 req/day |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) | **Yes** | Free account required |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | **Yes** | Free tier 1 000 checks/day |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | **Yes** | Paid membership for host lookups |
| `GREYNOISE_API_KEY` | [greynoise.io](https://www.greynoise.io) | Recommended | Free community tier available |
| `THREATFOX_API_KEY` | [threatfox.abuse.ch](https://threatfox.abuse.ch/api/) | Optional | Unauthenticated allowed, lower rate limit |
| `GITHUB_TOKEN` | GitHub → Settings → Developer Settings | Optional | Raises rate limit from 10 to 30 req/min |
| `FRONTEND_URL` | — | Optional | Production frontend origin added to CORS; defaults to `http://localhost:5173` |

MalwareBazaar, URLhaus, and CIRCL pDNS require no API key.

---

## v1 — Notebook

The original prototype queries WHOIS, GitHub, HaveIBeenPwned, Shodan, and VirusTotal and generates a structured markdown threat report.

**Cell 6 demonstrates a live indirect prompt injection attack** using a locally constructed poisoned WHOIS record. No external systems are queried in that cell.

```bash
cd notebook
pip install -r ../requirements.txt
jupyter notebook osint_report.ipynb
```

Set your target in Cell 2 then run all cells.

### Prompt Injection Risk — By Design

All data sources return unverified public content that flows into the LLM prompt. An adversary who anticipates being queried by an LLM-assisted tool can embed instruction payloads in WHOIS registrant fields, GitHub bios, Shodan banner data, or DNS records.

| Mitigation | Implementation | Limitation |
|---|---|---|
| Delimiter tags | External data wrapped in `<external_data>` tags | Sophisticated payloads can escape delimiter context |
| System/user separation | Trust instructions in system prompt, data in user message | Does not prevent all context blending |
| Model self-reporting | LLM instructed to flag detected injection attempts | Soft control — model can be deceived |
| Analyst warning banner | Injection flag surfaced visually in notebook output | Depends on analyst reading the warning |

**No mitigation substitutes for human analyst review before acting on output.**

This tool is a companion to the research paper:
> *Vulnerability Landscape of Large Language Models: Attack Vectors, Exploitation Techniques, and Defensive Controls* (2026)

---

## Before Committing (Notebook)

Clear cell outputs before every commit to prevent accidental exposure of query results:

```bash
jupyter nbconvert --clear-output --inplace notebook/osint_report.ipynb
```

---

## Authorization Notice

Query only targets you are authorized to research. Public availability of data does not imply authorization to collect or analyze it. This tool is intended for authorized threat intelligence research, security assessments, and educational demonstration only.

---

## Roadmap

- [x] WHOIS lookup
- [x] FastAPI backend with async concurrent fan-out
- [x] React frontend with real-time scan pipeline UI
- [x] AI triage report via Claude API (structured JSON — verdict, confidence, MITRE, TLP)
- [x] AlienVault OTX integration
- [x] GreyNoise integration
- [x] AbuseIPDB integration (365-day window)
- [x] Shodan integration (ports, CVEs)
- [x] MalwareBazaar integration
- [x] URLhaus integration
- [x] CIRCL Passive DNS integration
- [x] VirusTotal Passive DNS with communicating-file fallback
- [x] ThreatFox integration
- [x] GitHub search with proxy-list relevance filtering
- [x] Input type auto-detection (IP / domain / hash / URL / email)
- [x] Batch analysis endpoint (`POST /analyze/batch`, semaphore-limited to 10 concurrent)
- [x] Clickable source links in Sources tab (per-source external URLs)
- [x] JSON and PDF report export
- [x] Prompt injection demonstration and mitigation (v1)
- [ ] STIX 2.1 structured report output
- [ ] HaveIBeenPwned integration in v2
- [ ] Deployed live demo

---

## Related Work

- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org)
- Greshake et al. (2023) — *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*
- Anthropic Prompt Engineering Guide — Input Validation and Injection Defense

---

## License

MIT — see LICENSE file for details.

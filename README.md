# SentinelOSINT — IOC Enrichment & Triage

**LLM-assisted indicator of compromise enrichment across 11 concurrent intelligence sources, with multi-IOC campaign analysis and an independent accuracy benchmark**

---

## Live Demo

**[sentinel-osint-r7fv.onrender.com](https://sentinel-osint-r7fv.onrender.com)**

> Hosted on Render's free tier — allow ~30 seconds for cold start if the app has been inactive.
> Demo mode serves pre-cached results; no API keys are required to explore the UI.

---

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React-61DAFB)](https://react.dev)
[![Claude](https://img.shields.io/badge/LLM-Anthropic%20Claude-orange)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Overview

SentinelOSINT is a full-stack IOC enrichment and triage platform. Submit an IP address, domain, file hash, or URL and it fans out to eleven threat intelligence sources concurrently, then passes the aggregated results to Claude to produce a structured triage assessment — verdict, confidence breakdown, MITRE ATT&CK mappings, recommended actions, and TLP classification.

**Campaign Analysis mode** lets you submit a collection of related indicators together (IPs, domains, and hashes from the same incident) and receive a unified campaign-level assessment: whether the indicators appear to be coordinated, what shared patterns tie them together, infrastructure role classification (C2, delivery, exfiltration), and a threat actor hypothesis.

An independent **benchmark suite** in `benchmark/` evaluates the tool's classification accuracy against a curated ground truth dataset of 40 IP addresses (20 benign, 20 malicious) sourced from public threat intelligence feeds.

This project exists in two versions:

| Version | Description | Entry Point |
|---|---|---|
| **v1 — Notebook** | Jupyter-based prototype. Includes a live prompt injection demonstration and mitigation analysis. | `notebook/osint_report.ipynb` |
| **v2 — Full Stack** | Production-grade FastAPI backend + React frontend with single-IOC and campaign analysis modes. | `backend/` + `frontend/` |

---

## Features

### Single-IOC Analysis
- Fan-out to 11 concurrent intelligence sources via `asyncio.gather`
- LLM triage report with verdict, three-component confidence score, MITRE ATT&CK mapping, recommended actions, and TLP
- Input type auto-detection (IP, domain, URL, MD5, SHA1, SHA256, email)
- Tabs: Summary, Indicators, Sources (with external links), AI Report
- JSON and PDF export
- Friendly-name alias resolution (e.g. "Google DNS" → 8.8.8.8)

### Campaign Analysis
- Paste multiple related indicators (one per line) into a textarea
- All indicators run through the full 11-source pipeline concurrently
- LLM synthesizes a campaign-level report: shared patterns, infrastructure map grouped by role (C2 / delivery / exfiltration), threat actor hypothesis, campaign verdict and confidence
- Infrastructure map rendered as a grouped card view in the UI

### Benchmark
- Ground truth dataset: 20 known-benign IPs (DNS resolvers, CDNs) + 20 known-malicious IPs (Feodo Tracker, AbuseIPDB, Spamhaus)
- `benchmark/run_benchmark.py` loops all 40 targets through the live API, computes precision, recall, FPR, FNR, F1, and accuracy under lenient and strict thresholds, and saves a full per-target results report
- See [`benchmark/README.md`](benchmark/README.md) for methodology and dataset sources

### Demo Mode
- Pre-loaded single-target examples: Tor exit node (malicious IP), C2 domain, Google DNS (benign IP), EICAR test hash
- Pre-loaded campaign examples: Banking Phishing Kit (4 indicators), Cobalt Strike C2 Cluster (4 indicators)
- Set `DEMO_MODE=true` in the environment to serve cached results without API keys

---

## Data Sources

Sources that don't apply to the input type return `status: "not_applicable"` and are excluded from the LLM context automatically.

| Source | Covers | Key signals |
|---|---|---|
| **WHOIS / RDAP** | Domain, IP | Registrar, creation date, nameservers, ASN, country (IP via RDAP) |
| **AlienVault OTX** | IP, Domain, URL, Hash | Pulse count, malware families, threat actors, reputation score |
| **GreyNoise** | IP only | Mass-scanner classification, RIOT benign-service list |
| **AbuseIPDB** | IP only | Abuse confidence score (0–100), 365-day report count, categories |
| **Shodan** | IP only | Open ports, service banners, CVEs (CVSS ≥ 9.0 flagged) |
| **MalwareBazaar** | MD5, SHA1, SHA256 | Malware signature, file type, community tags |
| **URLhaus** | URL, Domain | Active/offline malicious URL count, tags |
| **CIRCL Passive DNS** | IP, Domain | Historical DNS resolutions |
| **VirusTotal Passive DNS** | IP, Domain | DNS resolutions; falls back to communicating/referrer files |
| **GitHub** | All | Repository search with proxy-list relevance filtering |
| **ThreatFox** | IP, Domain | IOC entries, confidence level, threat type, malware family |

---

## LLM Reports

### Single-IOC report

After all sources resolve, Claude synthesizes a structured JSON assessment:

```json
{
  "verdict": "malicious | suspicious | benign | unknown",
  "source_confidence": 92,
  "llm_confidence": 87,
  "overall_confidence": 90,
  "summary": "2–3 sentence plain English summary for non-technical stakeholders",
  "key_findings": ["finding 1", "finding 2", "finding 3"],
  "mitre_techniques": [
    { "technique_id": "T1583.001", "technique_name": "Acquire Infrastructure: Domains", "justification": "..." }
  ],
  "recommended_actions": ["Block at perimeter firewall", "Search SIEM for last 90 days"],
  "iocs_extracted": ["associated IOCs found in source data"],
  "tlp": "WHITE | GREEN | AMBER",
  "top_supporting_evidence": ["strongest signal 1 with source and value"],
  "top_conflicting_evidence": ["signal that introduces uncertainty or false-positive risk"]
}
```

**Confidence fields:**
- `source_confidence` — quality, quantity, and agreement of raw source data (independently of the model's interpretation)
- `llm_confidence` — the model's certainty in its own reasoning and interpretation
- `overall_confidence` — weighted combination: `round((source_confidence × 0.6) + (llm_confidence × 0.4))`

### Campaign report

Campaign analysis produces a separate structured assessment:

```json
{
  "campaign_verdict": "coordinated_malicious | likely_related | unrelated | unknown",
  "confidence": 94,
  "summary": "3–4 sentence plain English assessment for a CISO or incident commander",
  "shared_patterns": ["All three domains registered via Namecheap within 48 hours", "..."],
  "infrastructure_map": {
    "c2":           ["45.153.160.140", "194.165.16.158"],
    "delivery":     ["malicious-domain.xyz"],
    "exfiltration": ["185.234.219.70"],
    "unknown":      []
  },
  "threat_actor_hypothesis": "Named group or behavioral profile; null if unknown",
  "mitre_techniques": [
    { "technique_id": "T1583.001", "technique_name": "Acquire Infrastructure: Domains", "justification": "..." }
  ],
  "recommended_actions": ["Campaign-level action 1", "Campaign-level action 2"]
}
```

---

## API

### Single target
```
GET /api/analyze?target={ip|domain|hash|url}
```

### Batch (up to 10 concurrent)
```
POST /api/analyze/batch
Content-Type: application/json

{ "targets": ["1.1.1.1", "evil.com", "abc123..."] }
```

### Campaign analysis
```
POST /api/analyze/campaign
Content-Type: application/json

{ "targets": ["185.220.101.47", "malicious-domain.xyz", "45.153.160.140"] }
```

Response:
```json
{
  "targets": ["185.220.101.47", "malicious-domain.xyz", "45.153.160.140"],
  "individual_results": [ { "target": "...", "report": { ... }, ... } ],
  "campaign_report": { "campaign_verdict": "...", "shared_patterns": [...], ... }
}
```

### Single-target response shape
```json
{
  "target": "185.220.101.47",
  "input_type": "ip",
  "whois":          { "asn": "AS209100", "org": "...", "country": "DE", ... },
  "otx":            { "source": "otx",        "status": "success", "verdict": "malicious", "confidence": "high", "summary": "...", "raw": { ... } },
  "greynoise":      { "source": "greynoise",  "status": "success", "verdict": "malicious", "confidence": "high", "summary": "...", "raw": { ... } },
  "abuseipdb":      { "source": "abuseipdb",  "status": "success", "verdict": "malicious", "confidence": "high", "summary": "...", "raw": { ... } },
  "shodan":         { "source": "shodan",     "status": "success", "verdict": "suspicious","confidence": "medium","summary": "...", "raw": { ... } },
  "malwarebazaar":  { "source": "malwarebazaar",  "status": "not_applicable", ... },
  "urlhaus":        { "source": "urlhaus",        "status": "not_applicable", ... },
  "circl_pdns":     { "source": "circl_pdns",     "status": "success", ... },
  "vt_passive_dns": { "source": "vt_passive_dns", "status": "success", ... },
  "github":         { "source": "github",         "status": "success", ... },
  "threatfox":      { "source": "threatfox",      "status": "success", "verdict": "malicious", ... },
  "report": {
    "verdict": "malicious",
    "source_confidence": 96,
    "llm_confidence": 87,
    "overall_confidence": 92,
    "summary": "...",
    ...
  }
}
```

Each source follows `{source, status, verdict, confidence, summary, raw}`. Sources returning `status: "not_applicable"` are excluded from the LLM prompt automatically.

---

## Run Locally

**Backend**
```bash
cd backend
pip install -r requirements.txt
cp ../.env.example .env   # fill in your API keys
python -m uvicorn main:app --reload
# API available at http://localhost:8000
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
# UI at http://localhost:5173 — Vite proxies /api/* to the backend
```

**Demo mode (no API keys required)**
```bash
DEMO_MODE=true python -m uvicorn main:app --reload
```

**Run the benchmark**
```bash
pip install httpx
# backend must be running on localhost:8000
python benchmark/run_benchmark.py
# results saved to benchmark/results.json
```

---

## Project Structure

```
sentinel-osint/
├── backend/
│   ├── main.py                 # FastAPI routes — single, batch, and campaign /analyze endpoints
│   ├── fetchers.py             # 11 async source integrations, single-IOC and campaign LLM reports
│   ├── fetch_threatfox.py      # ThreatFox module (standalone)
│   ├── demo_data/              # Pre-cached results served in DEMO_MODE
│   │   ├── manifest.json       # Ordered demo target list (single + campaign entries)
│   │   ├── 185.220.101.45.json
│   │   ├── malware-c2.example.json
│   │   ├── 8.8.8.8.json
│   │   ├── 44d88612fea8a8f36de82e1278abb02f.json
│   │   ├── campaign_phishing_kit.json    # Multi-bank phishing campaign demo
│   │   └── campaign_cobalt_strike.json   # Cobalt Strike C2 cluster demo
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Full UI — single-IOC and campaign modes, all tabs
│   │   └── main.jsx
│   ├── index.html
│   ├── vite.config.js          # Dev proxy: /api/* → localhost:8000
│   └── package.json
├── benchmark/
│   ├── ground_truth.json       # 20 benign + 20 malicious IPs with source attribution
│   ├── run_benchmark.py        # Accuracy evaluation script (precision, recall, FPR, FNR)
│   └── README.md               # Methodology, dataset sources, metric definitions
├── notebook/
│   └── osint_report.ipynb      # v1 prototype with prompt injection demo
├── modules/                    # v1 notebook helper modules
├── .env.example
├── .gitignore
└── README.md
```

---

## API Keys

Copy `.env.example` to `backend/.env`. Never commit `.env`.

| Variable | Source | Required | Notes |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | **Yes** | Single-IOC and campaign report generation |
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) | **Yes** | Passive DNS; free tier 500 req/day |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) | **Yes** | Free account required |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | **Yes** | Free tier 1,000 checks/day |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | **Yes** | Paid membership for host lookups |
| `GREYNOISE_API_KEY` | [greynoise.io](https://www.greynoise.io) | Recommended | Free community tier available |
| `THREATFOX_API_KEY` | [threatfox.abuse.ch](https://threatfox.abuse.ch/api/) | Optional | Unauthenticated access allowed, lower rate limit |
| `GITHUB_TOKEN` | GitHub → Settings → Developer Settings | Optional | Raises rate limit from 10 to 30 req/min |
| `FRONTEND_URL` | — | Optional | Production CORS origin; defaults to `http://localhost:5173` |
| `DEMO_MODE` | — | Optional | Set `true` to serve pre-cached demo results |

MalwareBazaar, URLhaus, and CIRCL pDNS require no API key.

---

## Benchmark

The `benchmark/` directory contains an independent accuracy evaluation against a curated ground truth dataset.

**Dataset:** 40 IP addresses — 20 known-benign (public DNS resolvers, major CDN/cloud infrastructure) and 20 known-malicious (sourced from Feodo Tracker, AbuseIPDB, and Spamhaus), each with documented source attribution.

**Metrics computed:** Precision, Recall (TPR), False Positive Rate, False Negative Rate, F1 Score, Accuracy — evaluated under two thresholds:
- **Lenient:** `malicious` or `suspicious` verdict counts as a positive prediction
- **Strict:** only `malicious` verdict counts as a positive prediction

See [`benchmark/README.md`](benchmark/README.md) for full methodology, dataset sources, and known caveats (IP reassignment, Tor exit node ambiguity, LLM non-determinism).

```bash
python benchmark/run_benchmark.py --help
# --api-url, --delay, --strict, --output, --targets
```

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

This tool accompanies the research paper:
> *Vulnerability Landscape of Large Language Models: Attack Vectors, Exploitation Techniques, and Defensive Controls* (2026)

---

## Before Committing (Notebook)

Clear cell outputs before every commit:

```bash
jupyter nbconvert --clear-output --inplace notebook/osint_report.ipynb
```

---

## Authorization Notice

Query only targets you are authorized to research. Public availability of data does not imply authorization to collect or analyze it. This tool is intended for authorized threat intelligence research, security assessments, and educational demonstration only.

---

## Roadmap

- [x] WHOIS lookup (domain WHOIS + IP RDAP via ipwhois)
- [x] FastAPI backend with async concurrent fan-out to 11 sources
- [x] React frontend with real-time scan pipeline UI
- [x] AI triage report via Claude API (structured JSON — verdict, confidence, MITRE, TLP)
- [x] Three-component confidence score (source quality, model certainty, weighted overall)
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
- [x] Batch analysis endpoint (`POST /api/analyze/batch`, semaphore-limited to 10 concurrent)
- [x] **Campaign analysis** — multi-IOC correlated assessment with infrastructure role classification
- [x] Campaign mode UI — textarea input, mode toggle, grouped infrastructure card view
- [x] Demo campaigns — Banking Phishing Kit and Cobalt Strike C2 Cluster pre-loaded examples
- [x] Accuracy benchmark — 40-target ground truth dataset, precision/recall/FPR/FNR evaluation
- [x] Clickable source links in Sources tab
- [x] JSON and PDF report export
- [x] Prompt injection demonstration and mitigation (v1)
- [x] Deployed live demo ([sentinel-osint-r7fv.onrender.com](https://sentinel-osint-r7fv.onrender.com))
- [ ] STIX 2.1 structured report output
- [ ] HaveIBeenPwned integration in v2
- [ ] Campaign history / session persistence

---

## Related Work

- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org)
- Greshake et al. (2023) — *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*
- Anthropic Prompt Engineering Guide — Input Validation and Injection Defense

---

## License

MIT — see LICENSE file for details.

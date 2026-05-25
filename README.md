# OSINT Threat Intelligence Tool

**LLM-Assisted Infrastructure and Identity Analysis**

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React-61DAFB)](https://react.dev)
[![LLM](https://img.shields.io/badge/LLM-Anthropic%20Claude-orange)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Overview

An LLM-assisted OSINT pipeline that aggregates data from WHOIS, VirusTotal, GitHub, and Reddit, then passes the structured results to an Anthropic Claude model to generate a formatted threat intelligence report.

This project exists in two versions:

| Version | Description | Entry Point |
|---|---|---|
| **v1 — Notebook** | Jupyter-based prototype. Includes a live prompt injection demonstration and mitigation analysis. | `notebook/osint_report.ipynb` |
| **v2 — Full Stack** | Production-grade FastAPI backend + React frontend with real-time scan UI and AI-generated reports. | `backend/` + `frontend/` |

Built to demonstrate:
- LLM-assisted OSINT collection and report generation
- **Indirect prompt injection risk** in AI-powered intelligence pipelines
- Practical mitigations for LLM input trust boundary violations
- Full-stack AI application engineering (REST API + React UI)
- Applied threat intelligence tradecraft in an AI engineering context

---

## v2 — Full Stack Demo

The v2 interface accepts a domain, IP, or username, fans out to four data sources concurrently, and generates a structured AI threat assessment in real time.

**Stack:** FastAPI · React · Vite · Anthropic Claude · VirusTotal API · GitHub API · Reddit API · python-whois

### Run Locally

**Backend**
```bash
cd backend
pip install -r requirements.txt
# Add your API keys to .env (see .env.example)
python -m uvicorn main:app --reload
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` — the Vite proxy forwards `/analyze` requests to the FastAPI backend on port 8000.

### API

```
GET /analyze?target={domain|ip|username}
```

Returns a unified JSON response:

```json
{
  "target": "example.com",
  "whois": { ... },
  "virustotal": { "reputation": { ... }, "indicators": [ ... ] },
  "github": { "found": true, "repos": [ ... ] },
  "reddit": { "posts": [ ... ] },
  "report": "AI-generated threat assessment..."
}
```

---

## v1 — Jupyter Notebook

The original prototype queries five sources — WHOIS, GitHub, HaveIBeenPwned, Shodan, and VirusTotal — and generates a structured markdown threat report.

**Cell 6 demonstrates a live indirect prompt injection attack** using a locally constructed poisoned WHOIS record. No external systems are queried in that cell.

### Run

```bash
cd notebook
pip install -r requirements.txt
jupyter notebook osint_report.ipynb
```

Set your target in Cell 2, then run all cells.

### Prompt Injection Risk — By Design

All five data sources return unverified public content that flows into the LLM prompt. An adversary who anticipates being queried by an LLM-assisted tool can embed instruction payloads in WHOIS registrant fields, GitHub bios, Shodan banner data, or VirusTotal community comments.

| Mitigation | Implementation | Limitation |
|---|---|---|
| Delimiter tags | External data wrapped in `<external_data>` tags | Sophisticated payloads can escape delimiter context |
| System/user separation | Trust instructions in system prompt, data in user message | Does not prevent all context blending |
| Model self-reporting | LLM instructed to flag detected injection attempts | Soft control — model can be deceived |
| Analyst warning banner | Injection flag surfaced visually in notebook output | Depends on analyst reading the warning |

**No mitigation substitutes for human analyst review before acting on output.**

This tool is a companion to the research paper:
> *Vulnerability Landscape of Large Language Models: Attack Vectors, Exploitation Techniques, and Defensive Controls* (2026)

The injection demonstration in Cell 6 operationalizes the vulnerability class documented in Sections 3 and 15 of that paper.

---

## Project Structure

```
osint-llm-analyst/
├── notebook/
│   ├── osint_report.ipynb      # Main notebook — run this
│   ├── llm_analyst.py          # Anthropic API integration
│   └── modules/
│       ├── whois_lookup.py
│       ├── github_recon.py
│       ├── hibp_lookup.py
│       ├── shodan_lookup.py
│       └── virustotal_lookup.py
├── backend/
│   ├── main.py                 # FastAPI routes
│   ├── fetchers.py             # Async data source integrations
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main UI component
│   │   └── main.jsx
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
├── .env.example
├── .gitignore
└── README.md
```

---

## Setup

### API Keys Required

| Key | Source | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | Required for report generation |
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) | Free tier: 500 req/day |
| `GITHUB_TOKEN` | GitHub → Settings → Developer Settings | Optional; raises rate limit to 30 req/min |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | v1 notebook only |
| `HIBP_API_KEY` | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) | v1 notebook only; ~$4/year |

Copy `.env.example` to `.env` and fill in your keys. Never commit `.env`.

---

## Before Committing (Notebook)

Clear cell outputs before every commit to prevent accidental exposure of query results:

```bash
jupyter nbconvert --clear-output --inplace notebook/osint_report.ipynb
git add .
git commit -m "your message"
```

---

## Authorization Notice

Query only domains, accounts, and email addresses you are authorized to research. Public availability of data does not imply authorization to collect or analyze it. This tool is intended for authorized threat intelligence research, security assessments, and educational demonstration only.

---

## Roadmap

- [x] WHOIS, GitHub, Reddit, VirusTotal integration
- [x] FastAPI backend with async concurrent data fetching
- [x] React frontend with real-time scan UI
- [x] AI-generated threat narrative via Claude API
- [x] JSON and PDF report export
- [x] Prompt injection demonstration and mitigation (v1)
- [ ] Shodan integration in v2 backend
- [ ] HaveIBeenPwned integration in v2 backend
- [ ] STIX 2.1 structured report output
- [ ] Batch target processing
- [ ] Deployed live demo

---

## Related Work

- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org)
- Greshake et al. (2023) — *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*
- Anthropic Prompt Engineering Guide — Input Validation and Injection Defense

---

## License

MIT License — see LICENSE file for details.

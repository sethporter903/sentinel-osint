import asyncio
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fetchers import (
    fetch_whois,
    fetch_virustotal,
    fetch_github,
    fetch_reddit,
    generate_llm_report,
)

app = FastAPI(title="SentinelOSINT API", version="0.1.0")

# Allow your React frontend to call this API locally
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "ok", "message": "SentinelOSINT API is running"}


@app.get("/analyze")
async def analyze(target: str = Query(..., description="Domain, IP, or username to analyze")):
    """
    Fan out to all OSINT sources concurrently, then generate an LLM report.
    """
    whois_data, vt_data, github_data, reddit_data = await asyncio.gather(
        fetch_whois(target),
        fetch_virustotal(target),
        fetch_github(target),
        fetch_reddit(target),
    )

    report = await generate_llm_report(target, whois_data, vt_data, github_data, reddit_data)

    return {
        "target": target,
        "whois": whois_data,
        "virustotal": vt_data,
        "github": github_data,
        "reddit": reddit_data,
        "report": report,
    }

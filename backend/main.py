import os
import asyncio
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from dotenv import load_dotenv
from fetchers import (
    fetch_whois,
    fetch_otx,
    fetch_greynoise,
    fetch_abuseipdb,
    fetch_shodan,
    fetch_malwarebazaar,
    fetch_urlhaus,
    fetch_circl_pdns,
    fetch_vt_passive_dns,
    fetch_github,
    generate_ioc_report,
    detect_input_type,
)
from fetch_threatfox import fetch_threatfox

load_dotenv()

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

app = FastAPI(title="SentinelOSINT API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=list({"http://localhost:3000", "http://localhost:5173", FRONTEND_URL}),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "ok", "message": "SentinelOSINT API is running"}


async def _analyze_target(target: str) -> dict:
    input_type = detect_input_type(target)

    (
        whois_data,
        otx_data,
        greynoise_data,
        abuseipdb_data,
        shodan_data,
        malwarebazaar_data,
        urlhaus_data,
        circl_data,
        vt_pdns_data,
        github_data,
        threatfox_data,
    ) = await asyncio.gather(
        fetch_whois(target),
        fetch_otx(target),
        fetch_greynoise(target),
        fetch_abuseipdb(target),
        fetch_shodan(target),
        fetch_malwarebazaar(target),
        fetch_urlhaus(target),
        fetch_circl_pdns(target),
        fetch_vt_passive_dns(target),
        fetch_github(target),
        fetch_threatfox(target),
    )

    all_sources = {
        "whois": whois_data,
        "otx": otx_data,
        "greynoise": greynoise_data,
        "abuseipdb": abuseipdb_data,
        "shodan": shodan_data,
        "malwarebazaar": malwarebazaar_data,
        "urlhaus": urlhaus_data,
        "circl_pdns": circl_data,
        "vt_passive_dns": vt_pdns_data,
        "github": github_data,
        "threatfox": threatfox_data,
    }

    relevant_sources = {
        k: v for k, v in all_sources.items()
        if not (isinstance(v, dict) and v.get("status") == "not_applicable")
    }

    report = await generate_ioc_report(target, input_type, relevant_sources)

    return {
        "target": target,
        "input_type": input_type,
        **all_sources,
        "report": report,
    }


@app.get("/analyze")
async def analyze(target: str = Query(..., description="Domain, IP, hash, or URL to analyze")):
    """
    Fan out to all IOC enrichment sources concurrently, then generate an LLM triage report.
    """
    return await _analyze_target(target)


class BatchRequest(BaseModel):
    targets: List[str]


@app.post("/analyze/batch")
async def analyze_batch(body: BatchRequest):
    """
    Analyze a list of IOCs concurrently, bounded to 10 in-flight requests at a time.
    """
    semaphore = asyncio.Semaphore(10)

    async def analyze_one(t: str) -> dict:
        async with semaphore:
            return await _analyze_target(t)

    results = await asyncio.gather(*[analyze_one(t) for t in body.targets])
    return list(results)

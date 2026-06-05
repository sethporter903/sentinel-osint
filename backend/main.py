import os
import json
import asyncio
from pathlib import Path
from fastapi import FastAPI, APIRouter, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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
    generate_campaign_report,
    detect_input_type,
)
from fetch_threatfox import fetch_threatfox

load_dotenv()

FRONTEND_URL  = os.getenv("FRONTEND_URL", "http://localhost:5173")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
DEMO_MODE     = os.getenv("DEMO_MODE", "false").lower() == "true"

# ── Demo data ─────────────────────────────────────────────────────────────────
# Load all cached result files from demo_data/ at startup.
# The manifest.json drives the ordered list shown in the frontend.

_DEMO_DIR = Path(__file__).parent / "demo_data"

def _load_demo_data() -> tuple[dict, list]:
    """Returns (cache_dict keyed by target, manifest_list)."""
    cache: dict[str, dict] = {}
    manifest: list[dict]   = []

    if not _DEMO_DIR.exists():
        return cache, manifest

    # Load manifest for ordered display + labels
    manifest_path = _DEMO_DIR / "manifest.json"
    if manifest_path.exists():
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)

    # Load each result file; filename stem == target string
    for path in _DEMO_DIR.glob("*.json"):
        if path.name == "manifest.json":
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            target_key = path.stem.lower()
            cache[target_key] = data
        except Exception:
            pass

    return cache, manifest


DEMO_CACHE, DEMO_MANIFEST = _load_demo_data()

# ── App ───────────────────────────────────────────────────────────────────────

app    = FastAPI(title="SentinelOSINT API", version="0.3.0")
router = APIRouter()

app.add_middleware(
    CORSMiddleware,
    allow_origins=list({"http://localhost:3000", "http://localhost:5173", FRONTEND_URL}),
    allow_methods=["*"],
    allow_headers=["*"],
)


@router.get("/")
async def root():
    return {
        "status": "ok",
        "message": "SentinelOSINT API is running",
        "demo_mode": DEMO_MODE,
        "demo_targets": DEMO_MANIFEST if DEMO_MODE else [],
    }


# ── Core analysis logic ───────────────────────────────────────────────────────

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


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/analyze")
async def analyze(target: str = Query(..., description="Domain, IP, hash, or URL to analyze")):
    """
    Fan out to all IOC enrichment sources concurrently, then generate an LLM triage report.
    In DEMO_MODE, returns pre-cached results instead of making live API calls.
    """
    if DEMO_MODE:
        cached = DEMO_CACHE.get(target.lower().strip())
        if cached:
            return cached
        return {
            "demo_error": True,
            "message": (
                "Demo mode is active — this target isn't in the pre-loaded example set. "
                "Please select one of the available demo targets."
            ),
            "available_targets": [entry["target"] for entry in DEMO_MANIFEST],
        }

    return await _analyze_target(target)


class BatchRequest(BaseModel):
    targets: List[str]


class CampaignRequest(BaseModel):
    targets: List[str]


@router.post("/analyze/campaign")
async def analyze_campaign(body: CampaignRequest):
    """
    Analyze a set of related IOCs as a unified campaign.
    Runs each target through the full pipeline concurrently, then synthesizes
    all results into a campaign-level assessment via LLM.
    """
    if not body.targets:
        return {"error": "No targets provided"}

    semaphore = asyncio.Semaphore(10)

    async def analyze_one(t: str) -> dict:
        async with semaphore:
            return await _analyze_target(t)

    individual_results = list(await asyncio.gather(*[analyze_one(t) for t in body.targets]))
    campaign_report = await generate_campaign_report(individual_results)

    return {
        "targets": body.targets,
        "individual_results": individual_results,
        "campaign_report": campaign_report,
    }


@router.post("/analyze/batch")
async def analyze_batch(body: BatchRequest):
    """
    Analyze a list of IOCs concurrently, bounded to 10 in-flight requests at a time.
    In DEMO_MODE, each target is served from cache (or returns a demo_error entry).
    """
    if DEMO_MODE:
        results = []
        for t in body.targets:
            cached = DEMO_CACHE.get(t.lower().strip())
            results.append(cached if cached else {
                "demo_error": True,
                "target": t,
                "message": "Target not available in demo mode.",
            })
        return results

    semaphore = asyncio.Semaphore(10)

    async def analyze_one(t: str) -> dict:
        async with semaphore:
            return await _analyze_target(t)

    results = await asyncio.gather(*[analyze_one(t) for t in body.targets])
    return list(results)


# ── Router mounts ─────────────────────────────────────────────────────────────
_FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"

# Always expose routes at /api (used by the built frontend in production).
app.include_router(router, prefix="/api")

# In local dev the built frontend doesn't exist, so also mount routes at /
# (Vite's dev-server proxy strips /api before forwarding to this server).
if not _FRONTEND_DIST.exists():
    app.include_router(router)

# ── Frontend static files (production only) ───────────────────────────────────
# Serve the built React SPA. Must come AFTER all API route registrations so
# API paths are matched first; everything else falls through to index.html.
if _FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIST), html=True), name="frontend")

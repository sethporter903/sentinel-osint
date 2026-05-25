import whois
import os
import asyncio
import httpx
from functools import partial
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")


# ─────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────

async def fetch_whois(target: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        data = await loop.run_in_executor(None, partial(whois.whois, target))
        return {
            "registrar": data.registrar or "N/A",
            "created": str(data.creation_date[0] if isinstance(data.creation_date, list) else data.creation_date),
            "expires": str(data.expiration_date[0] if isinstance(data.expiration_date, list) else data.expiration_date),
            "registrant": data.name or "REDACTED",
            "country": data.country or "N/A",
            "nameservers": data.name_servers or [],
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# VIRUSTOTAL
# ─────────────────────────────────────────────

async def fetch_virustotal(target: str) -> dict:
    """
    Returns reputation data and passive DNS for a domain or IP.
    Free tier: 500 requests/day.
    """
    headers = {"x-apikey": VT_API_KEY}

    # Determine endpoint based on target type
    if _is_ip(target):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        indicators = []

        # Pull out malicious/suspicious detections as indicators
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            indicators.append({
                "type": "Reputation",
                "value": target,
                "source": "VirusTotal",
                "risk": "high" if malicious > 5 else "medium",
                "detail": f"{malicious} malicious, {suspicious} suspicious detections"
            })

        # Pull out associated IPs or subdomains if available
        for record in attrs.get("last_dns_records", [])[:5]:
            indicators.append({
                "type": record.get("type", "DNS"),
                "value": record.get("value", ""),
                "source": "VirusTotal DNS",
                "risk": "low",
            })

        return {
            "reputation": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            },
            "indicators": indicators,
            "tags": attrs.get("tags", []),
            "categories": attrs.get("categories", {}),
        }

    except httpx.HTTPStatusError as e:
        return {"error": f"VT API error: {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# GITHUB
# ─────────────────────────────────────────────

async def fetch_github(target: str) -> dict:
    """
    Searches GitHub repos and code for mentions of the target.
    Authenticated: 30 req/min. Unauthenticated: 10 req/min.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    search_url = "https://api.github.com/search/repositories"
    params = {"q": target, "sort": "updated", "per_page": 5}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(search_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

        repos = []
        for item in data.get("items", []):
            repos.append({
                "name": item.get("full_name"),
                "description": item.get("description", ""),
                "url": item.get("html_url"),
                "stars": item.get("stargazers_count", 0),
                "updated": item.get("updated_at", ""),
            })

        return {
            "found": len(repos) > 0,
            "total_count": data.get("total_count", 0),
            "repos": repos,
        }

    except httpx.HTTPStatusError as e:
        return {"error": f"GitHub API error: {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# REDDIT
# ─────────────────────────────────────────────

async def fetch_reddit(target: str) -> dict:
    """
    Searches Reddit for mentions of the target.
    No API key required — uses public JSON endpoint.
    """
    url = "https://www.reddit.com/search.json"
    params = {"q": target, "sort": "relevance", "limit": 10, "type": "link"}
    headers = {"User-Agent": "osint-tool/0.1 (portfolio project)"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

        posts = []
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            posts.append({
                "title": post.get("title", ""),
                "sub": f"r/{post.get('subreddit', '')}",
                "url": f"https://reddit.com{post.get('permalink', '')}",
                "score": post.get("score", 0),
                "created": post.get("created_utc", 0),
            })

        return {
            "found": len(posts) > 0,
            "posts": posts,
        }

    except httpx.HTTPStatusError as e:
        return {"error": f"Reddit API error: {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# LLM REPORT (Anthropic)
# ─────────────────────────────────────────────

async def generate_llm_report(target: str, whois_data: dict, vt_data: dict, github_data: dict, reddit_data: dict) -> str:
    """
    Sends aggregated OSINT data to Claude and returns a structured threat assessment.
    """
    prompt = f"""You are a threat intelligence analyst. In 2-3 paragraphs, assess the threat level of "{target}" based on this data:

WHOIS: {str(whois_data)[:500]}
VirusTotal: {str(vt_data)[:500]}
Reddit mentions: {len(reddit_data.get('posts', []))} posts found

Be concise and direct.
"""

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-5",
                    "max_tokens": 500,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]

    except Exception as e:
        return f"Report generation failed: {str(e)}"


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _is_ip(target: str) -> bool:
    """Simple check to distinguish IPs from domains."""
    parts = target.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)

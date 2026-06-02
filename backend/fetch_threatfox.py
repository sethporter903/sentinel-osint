"""
ThreatFox fetcher — abuse.ch IOC database.

Queries the ThreatFox REST API (https://threatfox.abuse.ch/api/) to check
whether a given IP address or domain is a known IOC.

Supported input types : ip, domain
Not applicable        : url, hash, email, unknown

The API key (THREATFOX_API_KEY) is optional — unauthenticated requests are
allowed but rate-limited more aggressively. Provide the key for production use.

Returns the standard project schema:
    {source, status, verdict, confidence, summary, raw}
"""

import os
import httpx
from dotenv import load_dotenv
from fetchers import detect_input_type

load_dotenv()

THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")

_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def fetch_threatfox(target: str) -> dict:
    input_type = detect_input_type(target)

    if input_type not in ("ip", "domain"):
        return {
            "source": "threatfox",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "ThreatFox lookup supports IPs and domains only.",
            "raw": {},
        }

    headers = {"Content-Type": "application/json"}
    if THREATFOX_API_KEY:
        headers["API-KEY"] = THREATFOX_API_KEY

    payload = {"query": "search_ioc", "search_term": target}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                _API_URL, headers=headers, json=payload, timeout=10
            )
            response.raise_for_status()
            data = response.json()

        query_status = data.get("query_status", "")

        if query_status == "no_result":
            return {
                "source": "threatfox",
                "status": "not_found",
                "verdict": "unknown",
                "confidence": "low",
                "summary": "No ThreatFox entries found for this target.",
                "raw": data,
            }

        if query_status != "ok":
            return {
                "source": "threatfox",
                "status": "error",
                "verdict": "unknown",
                "confidence": "low",
                "summary": f"ThreatFox returned unexpected status: {query_status}",
                "raw": data,
            }

        iocs = data.get("data") or []

        # ── Aggregate key fields across all returned IOC entries ──────────
        malware_families = list({
            entry.get("malware_printable") or entry.get("malware", "")
            for entry in iocs
            if entry.get("malware_printable") or entry.get("malware")
        })
        threat_types = list({
            entry.get("threat_type_desc") or entry.get("threat_type", "")
            for entry in iocs
            if entry.get("threat_type_desc") or entry.get("threat_type")
        })
        tags = list({
            tag
            for entry in iocs
            for tag in (entry.get("tags") or [])
        })

        # ThreatFox confidence_level: 100 = very high, 75 = high,
        # 50 = medium, 25 = low.  Use the highest value across all entries.
        max_confidence = max(
            (entry.get("confidence_level", 0) for entry in iocs), default=0
        )

        if max_confidence >= 75:
            verdict, confidence = "malicious", "high"
        elif max_confidence >= 50:
            verdict, confidence = "malicious", "medium"
        else:
            verdict, confidence = "suspicious", "low"

        families_str = f", malware: {', '.join(malware_families[:3])}" if malware_families else ""
        summary = (
            f"ThreatFox: {len(iocs)} IOC entry/entries "
            f"(max confidence {max_confidence}%){families_str}."
        )

        return {
            "source": "threatfox",
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": {
                "ioc_count": len(iocs),
                "iocs": iocs[:10],
                "malware_families": malware_families[:5],
                "threat_types": threat_types[:5],
                "tags": tags[:10],
                "max_confidence_level": max_confidence,
            },
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "threatfox",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"ThreatFox API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "threatfox",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }

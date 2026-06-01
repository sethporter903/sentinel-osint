import whois
import os
import re
import json
import asyncio
import httpx
from datetime import datetime, timezone
from functools import partial
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _is_ip(target: str) -> bool:
    parts = target.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def detect_input_type(target: str) -> str:
    if _is_ip(target):
        return "ip"
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    if re.fullmatch(r"[0-9a-fA-F]{32}", target):
        return "md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", target):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", target):
        return "sha256"
    if "@" in target and "." in target.split("@", 1)[1]:
        return "email"
    if "." in target:
        return "domain"
    return "unknown"


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
# ALIENVAULT OTX
# ─────────────────────────────────────────────

async def fetch_otx(target: str) -> dict:
    input_type = detect_input_type(target)

    type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
    }

    if input_type not in type_map:
        return {
            "source": "otx",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"OTX does not support input type: {input_type}",
            "raw": {},
        }

    otx_type = type_map[input_type]
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{target}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY or ""}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

        pulses = data.get("pulse_info", {}).get("pulses", [])
        pulse_count = data.get("pulse_info", {}).get("count", 0)

        malware_families = list({
            m.get("display_name", "")
            for p in pulses
            for m in p.get("malware_families", [])
            if m.get("display_name")
        })
        threat_actors = list({
            p.get("adversary", "")
            for p in pulses
            if p.get("adversary")
        })

        if pulse_count > 10:
            verdict, confidence = "malicious", "high"
        elif pulse_count > 3:
            verdict, confidence = "malicious", "medium"
        elif pulse_count > 0:
            verdict, confidence = "suspicious", "low"
        else:
            verdict, confidence = "unknown", "low"

        families_str = f", malware: {', '.join(malware_families[:3])}" if malware_families else ""
        summary = f"Found in {pulse_count} OTX pulse(s){families_str}."

        return {
            "source": "otx",
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": {
                "pulse_count": pulse_count,
                "malware_families": malware_families[:5],
                "threat_actors": threat_actors[:5],
                "reputation": data.get("reputation", 0),
                "indicator": data.get("indicator", target),
            },
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "otx",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"OTX API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "otx",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# GREYNOISE
# ─────────────────────────────────────────────

async def fetch_greynoise(target: str) -> dict:
    if not _is_ip(target):
        return {
            "source": "greynoise",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "GreyNoise only supports IP addresses.",
            "raw": {},
        }

    url = f"https://api.greynoise.io/v3/community/{target}"
    headers = {"key": GREYNOISE_API_KEY or ""}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "")
        name = data.get("name", "")

        if riot:
            verdict, confidence = "benign", "high"
            summary = f"IP belongs to known benign service ({name or 'unspecified'}) per GreyNoise RIOT."
        elif noise and classification == "malicious":
            verdict, confidence = "malicious", "high"
            summary = "IP is a classified malicious mass-scanner per GreyNoise."
        elif noise:
            verdict, confidence = "suspicious", "medium"
            summary = f"IP is performing mass internet scanning (noise=true, classification={classification or 'unclassified'})."
        else:
            verdict, confidence = "unknown", "low"
            summary = "IP not seen in GreyNoise dataset."

        return {
            "source": "greynoise",
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": data,
        }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {
                "source": "greynoise",
                "status": "not_found",
                "verdict": "unknown",
                "confidence": "low",
                "summary": "IP not found in GreyNoise database.",
                "raw": {},
            }
        return {
            "source": "greynoise",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"GreyNoise API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "greynoise",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# ABUSEIPDB
# ─────────────────────────────────────────────

async def fetch_abuseipdb(target: str) -> dict:
    if not _is_ip(target):
        return {
            "source": "abuseipdb",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "AbuseIPDB only supports IP addresses.",
            "raw": {},
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY or "",
        "Accept": "application/json",
    }
    params = {"ipAddress": target, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

        record = data.get("data", {})
        score = record.get("abuseConfidenceScore", 0)
        total_reports = record.get("totalReports", 0)
        usage_type = record.get("usageType", "Unknown")
        isp = record.get("isp", "")

        if score >= 80:
            verdict, confidence = "malicious", "high"
        elif score >= 50:
            verdict, confidence = "malicious", "medium"
        elif score >= 20:
            verdict, confidence = "suspicious", "low"
        else:
            verdict, confidence = "benign", "medium"

        summary = (
            f"AbuseIPDB score {score}/100 from {total_reports} report(s); "
            f"usage type: {usage_type}, ISP: {isp}."
        )

        return {
            "source": "abuseipdb",
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": record,
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "abuseipdb",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"AbuseIPDB API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "abuseipdb",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# SHODAN
# ─────────────────────────────────────────────

async def fetch_shodan(target: str) -> dict:
    if not _is_ip(target):
        return {
            "source": "shodan",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "Shodan host lookup only supports IP addresses.",
            "raw": {},
        }

    url = f"https://api.shodan.io/shodan/host/{target}"
    params = {"key": SHODAN_API_KEY or ""}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

        ports = data.get("ports", [])
        vulns = data.get("vulns", {}) or {}

        # Extract service summaries (port, transport, product, version)
        services = []
        for item in data.get("data", [])[:10]:
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
            })

        cve_list = list(vulns.keys())
        high_severity_cves = [
            cve for cve, info in vulns.items()
            if isinstance(info, dict) and float(info.get("cvss") or 0) >= 7.0
        ]

        if high_severity_cves:
            verdict, confidence = "suspicious", "high"
            summary = (
                f"Host exposes {len(ports)} port(s) and has {len(cve_list)} known CVE(s), "
                f"{len(high_severity_cves)} with CVSS ≥ 7.0: {', '.join(high_severity_cves[:3])}."
            )
        elif cve_list:
            verdict, confidence = "suspicious", "medium"
            summary = (
                f"Host exposes {len(ports)} port(s) with {len(cve_list)} known CVE(s): "
                f"{', '.join(cve_list[:3])}."
            )
        else:
            verdict, confidence = "unknown", "low"
            summary = f"Host exposes {len(ports)} port(s) with no known CVEs in Shodan."

        return {
            "source": "shodan",
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": {
                "ports": ports[:20],
                "services": services,
                "vulns": cve_list[:10],
                "hostnames": data.get("hostnames", [])[:5],
                "org": data.get("org", ""),
                "country": data.get("country_name", ""),
                "last_update": data.get("last_update", ""),
                "tags": data.get("tags", []),
            },
        }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {
                "source": "shodan",
                "status": "not_found",
                "verdict": "unknown",
                "confidence": "low",
                "summary": "IP not found in Shodan.",
                "raw": {},
            }
        return {
            "source": "shodan",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"Shodan API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "shodan",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# MALWAREBAZAAR
# ─────────────────────────────────────────────

async def fetch_malwarebazaar(target: str) -> dict:
    input_type = detect_input_type(target)
    if input_type not in ("md5", "sha1", "sha256"):
        return {
            "source": "malwarebazaar",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "MalwareBazaar only supports file hashes (MD5, SHA1, SHA256).",
            "raw": {},
        }

    url = "https://mb-api.abuse.ch/api/v1/"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, data={"query": "get_info", "hash": target}, timeout=15)
            response.raise_for_status()
            data = response.json()

        query_status = data.get("query_status", "")

        if query_status == "no_results":
            return {
                "source": "malwarebazaar",
                "status": "not_found",
                "verdict": "unknown",
                "confidence": "low",
                "summary": "Hash not found in MalwareBazaar.",
                "raw": data,
            }

        if query_status != "ok":
            return {
                "source": "malwarebazaar",
                "status": "error",
                "verdict": "unknown",
                "confidence": "low",
                "summary": f"MalwareBazaar returned unexpected status: {query_status}",
                "raw": data,
            }

        sample = (data.get("data") or [{}])[0]
        signature = sample.get("signature") or "unknown"
        file_type = sample.get("file_type", "")
        tags = sample.get("tags") or []

        summary = (
            f"Known malware: {signature} ({file_type}), "
            f"tags: {', '.join(tags[:5]) or 'none'}."
        )

        return {
            "source": "malwarebazaar",
            "status": "success",
            "verdict": "malicious",
            "confidence": "high",
            "summary": summary,
            "raw": {
                "sha256": sample.get("sha256_hash"),
                "md5": sample.get("md5_hash"),
                "file_type": file_type,
                "signature": signature,
                "tags": tags[:10],
                "first_seen": sample.get("first_seen"),
            },
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "malwarebazaar",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"MalwareBazaar API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "malwarebazaar",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# URLHAUS
# ─────────────────────────────────────────────

async def fetch_urlhaus(target: str) -> dict:
    input_type = detect_input_type(target)

    if input_type not in ("url", "domain"):
        return {
            "source": "urlhaus",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "URLhaus only supports URLs and domains.",
            "raw": {},
        }

    try:
        async with httpx.AsyncClient() as client:
            if input_type == "url":
                response = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": target},
                    timeout=15,
                )
            else:
                response = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": target},
                    timeout=15,
                )
            response.raise_for_status()
            data = response.json()

        query_status = data.get("query_status", "")

        if query_status == "no_results":
            return {
                "source": "urlhaus",
                "status": "not_found",
                "verdict": "unknown",
                "confidence": "low",
                "summary": "Target not found in URLhaus.",
                "raw": data,
            }

        urls = data.get("urls", [])
        active = [u for u in urls if u.get("url_status") == "online"]

        if active:
            verdict, confidence = "malicious", "high"
            summary = (
                f"Found in URLhaus: {len(active)} active malicious URL(s) "
                f"out of {len(urls)} total."
            )
        else:
            verdict, confidence = "suspicious", "medium"
            summary = (
                f"Found in URLhaus: {len(urls)} historical malicious URL(s), "
                f"all currently offline."
            )

        tags = list({t for u in urls for t in (u.get("tags") or [])})

        return {
            "source": "urlhaus",
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": {
                "url_count": len(urls),
                "active_count": len(active),
                "tags": tags[:10],
                "urls": urls[:5],
            },
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "urlhaus",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"URLhaus API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "urlhaus",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# CIRCL PASSIVE DNS
# ─────────────────────────────────────────────

async def fetch_circl_pdns(target: str) -> dict:
    input_type = detect_input_type(target)

    if input_type not in ("ip", "domain"):
        return {
            "source": "circl_pdns",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "CIRCL pDNS only supports domains and IPs.",
            "raw": {},
        }

    url = f"https://www.circl.lu/pdns/query/{target}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=15)
            response.raise_for_status()
            raw_text = response.text

        records = []
        for line in raw_text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue

        if not records:
            return {
                "source": "circl_pdns",
                "status": "not_found",
                "verdict": "unknown",
                "confidence": "low",
                "summary": "No passive DNS records found.",
                "raw": {"records": []},
            }

        rrnames = list({r.get("rrname", "") for r in records})
        rdatas = list({r.get("rdata", "") for r in records})

        summary = (
            f"Found {len(records)} pDNS record(s): "
            f"{len(rdatas)} unique resolution(s) across {len(rrnames)} name(s)."
        )

        return {
            "source": "circl_pdns",
            "status": "success",
            "verdict": "unknown",
            "confidence": "low",
            "summary": summary,
            "raw": {
                "record_count": len(records),
                "records": records[:20],
            },
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "circl_pdns",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"CIRCL pDNS API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "circl_pdns",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# VIRUSTOTAL PASSIVE DNS
# ─────────────────────────────────────────────

async def fetch_vt_passive_dns(target: str) -> dict:
    """
    Queries the VirusTotal resolutions endpoint for passive DNS history.

    For IPs  → /api/v3/ip_addresses/{ip}/resolutions  (domains that resolved here)
    For domains → /api/v3/domains/{domain}/resolutions (IPs the domain resolved to)

    If the resolutions endpoint returns no data, falls back in order to:
      1. communicating_files — malware samples seen connecting to this target
      2. referrer_files      — samples that embed / reference this target
    Fallback entries are labelled with a "type" key so callers can tell them apart
    from genuine pDNS records.

    Returns up to 10 entries, newest-first, under raw.passive_dns.
    """
    input_type = detect_input_type(target)

    if input_type not in ("ip", "domain"):
        return {
            "source": "vt_passive_dns",
            "status": "not_applicable",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "VT passive DNS only supports IPs and domains.",
            "raw": {"passive_dns": []},
        }

    if not VT_API_KEY:
        return {
            "source": "vt_passive_dns",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": "VT_API_KEY not configured.",
            "raw": {"passive_dns": []},
        }

    headers = {"x-apikey": VT_API_KEY}

    if input_type == "ip":
        base = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        hostname_key = "host_name"
    else:
        base = f"https://www.virustotal.com/api/v3/domains/{target}"
        hostname_key = "ip_address"

    res_url  = f"{base}/resolutions"
    comm_url = f"{base}/communicating_files"
    ref_url  = f"{base}/referrer_files"

    def _ts(ts) -> str:
        """Unix timestamp → YYYY-MM-DD string, or 'unknown'."""
        try:
            return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
        except (TypeError, ValueError, OSError):
            return "unknown"

    passive_dns: list = []
    fallback_used: str | None = None

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                res_url, headers=headers, params={"limit": 20}, timeout=10
            )
            resp.raise_for_status()
            res_data = resp.json()

        for item in res_data.get("data", []):
            attrs = item.get("attributes", {})
            hostname = attrs.get(hostname_key, "")
            if hostname:
                passive_dns.append({
                    "hostname": hostname,
                    "date": _ts(attrs.get("date", 0)),
                })

        # Newest-first, cap at 10
        passive_dns.sort(key=lambda x: x["date"], reverse=True)
        passive_dns = passive_dns[:10]

        # ── Fallback chain ──────────────────────────────────────────────
        if not passive_dns:
            for fb_url, fb_type in [
                (comm_url, "communicating_file"),
                (ref_url,  "referrer_file"),
            ]:
                async with httpx.AsyncClient() as client:
                    fb_resp = await client.get(
                        fb_url, headers=headers, params={"limit": 10}, timeout=10
                    )
                    fb_resp.raise_for_status()
                    fb_data = fb_resp.json()

                for item in fb_data.get("data", []):
                    attrs = item.get("attributes", {})
                    name = (
                        attrs.get("meaningful_name")
                        or (attrs.get("names") or [None])[0]
                        or item.get("id", "")
                    )
                    if name:
                        passive_dns.append({
                            "hostname": name,
                            "date": _ts(attrs.get("first_submission_date")),
                            "type": fb_type,
                        })

                if passive_dns:
                    fallback_used = fb_type
                    passive_dns = passive_dns[:10]
                    break

        # ── Verdict ─────────────────────────────────────────────────────
        if not passive_dns:
            verdict, confidence = "unknown", "low"
            summary = "No passive DNS records or file associations found in VirusTotal."
            status = "not_found"
        elif fallback_used == "communicating_file":
            verdict, confidence = "suspicious", "medium"
            summary = (
                f"No pDNS resolutions in VT; {len(passive_dns)} malware sample(s) "
                f"seen communicating with this target (communicating_files fallback)."
            )
            status = "success"
        elif fallback_used == "referrer_file":
            verdict, confidence = "suspicious", "low"
            summary = (
                f"No pDNS resolutions in VT; {len(passive_dns)} file(s) "
                f"reference this target (referrer_files fallback)."
            )
            status = "success"
        else:
            verdict, confidence = "unknown", "low"
            summary = (
                f"VirusTotal passive DNS: {len(passive_dns)} resolution(s) found."
            )
            status = "success"

        return {
            "source": "vt_passive_dns",
            "status": status,
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": {
                "passive_dns": passive_dns,
                "fallback_used": fallback_used,
                "total_returned": len(passive_dns),
            },
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "vt_passive_dns",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"VT API error: {e.response.status_code}",
            "raw": {"passive_dns": []},
        }
    except Exception as e:
        return {
            "source": "vt_passive_dns",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {"passive_dns": []},
        }


# ─────────────────────────────────────────────
# GITHUB
# ─────────────────────────────────────────────

# Compiled once at import time — used by the relevance scorer below.
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

_PROXY_NAME_KEYWORDS = frozenset({
    "proxy", "proxies", "proxylist", "proxy-list", "free-proxy",
    "socks", "socks5", "vpnlist", "vpn-list", "ip-list", "iplist",
    "ipblock", "blocklist", "block-list", "denylist", "deny-list",
})


def _score_github_relevance(repo: dict, target: str) -> bool:
    """
    Returns True when a GitHub search result likely contains *target* in a
    meaningful security context (config, script, threat-intel write-up, etc.)
    rather than inside a proxy list, massive IP dump, or obfuscated blob.

    Disqualifying conditions (any one → False):
      1. Description > 5 000 chars  ← almost always a data dump
      2. Description contains 50+ distinct IPs other than target  ← proxy list
      3. Target IP is surrounded by 3+ other IPs within a 200-char window  ← list row
      4. Repo name matches known proxy/list distribution patterns
      5. Description has > 30 % non-printable / non-ASCII chars  ← encoded blob
    """
    description = repo.get("description") or ""
    name = (repo.get("name") or "").lower()

    # 1. Description length guard
    if len(description) > 5_000:
        return False

    # 2. Count IPs in description; exclude the target itself
    all_desc_ips = _IP_RE.findall(description)
    if len([ip for ip in all_desc_ips if ip != target]) >= 50:
        return False

    # 3. Locality check — is the target surrounded by other IPs?
    target_pos = description.find(target)
    if target_pos != -1:
        window_start = max(0, target_pos - 100)
        window_end = min(len(description), target_pos + len(target) + 100)
        window_ips = _IP_RE.findall(description[window_start:window_end])
        if len([ip for ip in window_ips if ip != target]) >= 3:
            return False

    # 4. Repo name signals a list-distribution repository
    if any(kw in name for kw in _PROXY_NAME_KEYWORDS):
        return False

    # 5. High ratio of non-printable / non-ASCII chars → likely encoded blob
    if description:
        non_printable = sum(1 for c in description if ord(c) > 127 or ord(c) < 32)
        if non_printable / len(description) > 0.30:
            return False

    return True


async def fetch_github(target: str) -> dict:
    """
    Searches GitHub repositories for mentions of the target.
    Each result is tagged relevant: true/false via _score_github_relevance;
    only relevant results are surfaced in the summary and passed to the LLM.
    Authenticated: 30 req/min. Unauthenticated: 10 req/min.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    params = {"q": target, "sort": "updated", "per_page": 10}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/search/repositories",
                headers=headers,
                params=params,
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()

        repos = []
        for item in data.get("items", []):
            repos.append({
                "name": item.get("full_name"),
                "description": (item.get("description") or "")[:300],
                "url": item.get("html_url"),
                "stars": item.get("stargazers_count", 0),
                "updated": item.get("updated_at", ""),
                "topics": item.get("topics", [])[:5],
                "relevant": _score_github_relevance(item, target),
            })

        total_count = data.get("total_count", 0)
        relevant_repos = [r for r in repos if r["relevant"]]
        filtered_count = len(repos) - len(relevant_repos)

        if not repos:
            return {
                "source": "github",
                "status": "not_found",
                "verdict": "unknown",
                "confidence": "low",
                "summary": "Target not mentioned in any GitHub repository.",
                "raw": {"total_count": 0, "relevant_count": 0, "repos": []},
            }

        if not relevant_repos:
            summary = (
                f"GitHub returned {total_count} result(s) but all {filtered_count} "
                f"sampled were filtered as proxy lists or IP dumps — no meaningful context found."
            )
            verdict, confidence = "unknown", "low"
        else:
            summary = (
                f"GitHub: {len(relevant_repos)} relevant result(s) out of {total_count} total "
                f"({filtered_count} filtered as proxy lists or dumps)."
            )
            verdict, confidence = "suspicious", "low"

        return {
            "source": "github",
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "raw": {
                "total_count": total_count,
                "relevant_count": len(relevant_repos),
                "filtered_count": filtered_count,
                "repos": repos,
            },
        }

    except httpx.HTTPStatusError as e:
        return {
            "source": "github",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"GitHub API error: {e.response.status_code}",
            "raw": {},
        }
    except Exception as e:
        return {
            "source": "github",
            "status": "error",
            "verdict": "unknown",
            "confidence": "low",
            "summary": str(e),
            "raw": {},
        }


# ─────────────────────────────────────────────
# LLM IOC REPORT (Anthropic)
# ─────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a senior threat intelligence analyst with experience in federal law enforcement and cybercrime investigation. You will be given aggregated data about an IOC (Indicator of Compromise) from multiple sources. Your job is to synthesize this data into a structured triage assessment that a security team can act on immediately.

## Source Reliability Hierarchy
Weigh sources in this order when signals conflict:
1. Behavioral sandbox results and confirmed C2 activity (highest)
2. Multi-engine detection consensus (5+ engines agreeing)
3. AbuseIPDB reports with detailed category annotations
4. Shodan host data with CVE matches and exposed service fingerprints
5. GreyNoise classification with context
6. OTX pulse associations with named threat actors
7. Community reports and single-source flags (lowest)

## Interpretation Rules

**Age and detection count:**
- A domain or IP registered less than 30 days ago with LOW detections is MORE suspicious than an old domain with the same count — newly stood-up infrastructure hasn't been flagged yet
- A domain registered less than 7 days ago with ANY detections is high confidence malicious
- Old infrastructure (2+ years) with zero detections and clean WHOIS is a strong benign signal

**GreyNoise:**
- RIOT=true means the IP belongs to a known benign service (Google, Cloudflare, AWS, etc.) — treat as strong benign signal, likely a false positive
- noise=true + classification=malicious is high confidence malicious scanning infrastructure
- noise=true + classification=benign means mass scanning but from a known research or security entity — suspicious but not targeted
- noise=false + not in RIOT = IP is making targeted connections, not background noise — significantly raises suspicion

**AbuseIPDB:**
- Score 0-25: likely benign, low confidence either way
- Score 26-50: suspicious, worth investigating
- Score 51-80: significant, treat as malicious pending other context
- Score 81-100: high confidence malicious, recommend immediate block
- Always note the abuse categories (port scan vs. brute force vs. C2 traffic tell very different stories)

**Shodan:**
- Open ports on non-standard ranges (e.g. 4444, 6666, 1337, 8888) combined with generic or missing banners strongly suggest C2 or post-exploitation staging infrastructure
- CVEs with CVSS ≥ 9.0 on internet-exposed services should always surface in key_findings — these represent active attack surface, not just theoretical exposure
- A large number of distinct open services (10+) on a single IP is unusual and raises suspicion, especially if the org field shows a residential ISP or a cheap VPS provider
- Product fingerprints like Cobalt Strike team server, Metasploit, or known RAT default ports are high-confidence malicious indicators regardless of other source verdicts
- Shodan data tells you what is exposed, not who is responsible for the exposure — correlate with AbuseIPDB and OTX before drawing intent conclusions
- last_update timestamp matters: Shodan data older than 90 days may not reflect current state of a dynamic attacker IP

**Passive DNS (CIRCL pDNS + VirusTotal):**
- Two independent pDNS sources are provided; corroboration between them increases confidence
- Multiple domains resolving to a single IP over a short period suggests bulletproof hosting or fast-flux infrastructure
- Typosquats of known brands (paypa1.com, arnazon.com patterns) in passive DNS are high confidence phishing infrastructure
- Sudden DNS changes after a long stable period suggests infrastructure compromise or handoff
- VirusTotal passive DNS entries with a "type": "communicating_file" or "referrer_file" field are fallback data — no pDNS records exist in VT, but malware samples have been seen communicating with or referencing this target; treat as a suspicious signal of medium confidence
- If both pDNS sources return no records for a newly registered domain or IP, the absence of history is itself a mild suspicious signal (infrastructure too new to have accumulated records)

**OTX:**
- Pulse count above 5 from independent researchers significantly raises confidence
- Named threat actor associations should always surface in key_findings even if other signals are weak
- Malware family associations should map directly to MITRE ATT&CK techniques

**GitHub:**
- Results have already been filtered for relevance — only repositories where the target appears in a meaningful context (not proxy lists or IP dumps) are included; relevant_count tells you how many passed
- A relevant GitHub result means a researcher, developer, or incident responder explicitly referenced this IOC in a security tool, config file, or write-up — treat as corroborating intelligence
- High star counts on relevant repos increase confidence that the finding is legitimate and widely recognized
- Zero relevant results after filtering is neutral — it means the IOC is not publicly documented, not that it is clean
- If relevant_count > 0 and another source also flags the IOC, raise overall confidence one level

**Cross-source corroboration:**
- Two or more independent sources flagging the same IOC raises confidence one full level (low→medium, medium→high)
- A single source flag with no corroboration caps confidence at low regardless of the source's score
- Conflicting verdicts between sources should be explicitly noted in key_findings with your reasoning for the tiebreak

## MITRE ATT&CK Mapping Guidelines
- Malicious IP with open C2 ports → T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
- Fast-flux or bulletproof hosting → T1583.001 (Acquire Infrastructure: Domains)
- Typosquatting domains → T1583.001, T1566.002 (Phishing: Spearphishing Link)
- Credential harvesting infrastructure → T1056 (Input Capture), T1539 (Steal Web Session Cookie)
- Port scanning activity → T1046 (Network Service Discovery)
- Brute force reports → T1110 (Brute Force)
- Only include techniques you can directly justify from the source data — do not pad the list

## TLP Assignment
- WHITE: fully public data, safe to share broadly
- GREEN: can share within security community, not for public release
- AMBER: sensitive, share only with affected parties
- Default to GREEN for most IOCs. Use AMBER if passive DNS or OTX data reveals sensitive infrastructure details about a victim organization.

## Recommended Actions
Be specific. Not "investigate further" — instead:
- "Block this IP at perimeter firewall and search SIEM for connections in the last 90 days"
- "Search email gateway logs for messages containing this domain in links or headers"
- "Force password reset for any accounts that authenticated from this IP"
- "Submit to internal threat intel platform with associated pulse IDs for campaign tracking"
Tailor actions to the input type — IP actions differ from domain actions differ from hash actions.

## Output Rules
- Never hedge without quantifying uncertainty — give a verdict even when confidence is low
- The summary must be readable by a non-technical stakeholder (CISO, legal, HR) — no jargon
- key_findings should be the 3-5 most analytically significant observations, not a list of every data point
- iocs_extracted should include any additional IOCs found within the source data itself (associated domains, IPs, hashes mentioned in OTX pulses or AbuseIPDB reports)
- If all sources return not_applicable or not_found, return verdict: unknown with a summary explaining insufficient data

Return ONLY valid JSON matching this exact schema, no preamble, no markdown backticks:
{
  "verdict": "malicious" | "suspicious" | "benign" | "unknown",
  "confidence": "high" | "medium" | "low",
  "summary": "2-3 sentence plain English assessment a non-technical stakeholder can understand",
  "key_findings": ["finding 1", "finding 2", "finding 3"],
  "mitre_techniques": [{"technique_id": "T1583.001", "technique_name": "Acquire Infrastructure: Domains", "justification": "one sentence"}],
  "recommended_actions": ["specific action 1", "specific action 2"],
  "iocs_extracted": ["any additional IOCs found in the data"],
  "tlp": "WHITE" | "GREEN" | "AMBER"
}"""


async def generate_ioc_report(target: str, input_type: str, source_results: dict) -> dict:
    truncated = {k: str(v)[:800] for k, v in source_results.items()}

    user_message = (
        f"Target: {target}\n"
        f"Input type: {input_type}\n"
        f"Source data:\n{truncated}"
    )

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
                    "max_tokens": 1000,
                    "system": _SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": user_message}],
                },
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()
            text = data["content"][0]["text"]

        try:
            clean = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            return json.loads(clean)
        except (json.JSONDecodeError, ValueError):
            return text

    except Exception as e:
        return {"error": f"Report generation failed: {str(e)}"}

"""
virustotal_lookup.py
--------------------
Queries the VirusTotal v3 API for domain reputation, vendor detections,
and category data relevant to threat intelligence analysis.

Requires a VirusTotal API key. Free keys are available at:
https://www.virustotal.com/gui/join-us

Free-tier rate limit: 4 requests/minute, 500 requests/day.
"""

import requests


VT_API = "https://www.virustotal.com/api/v3"


def get_virustotal_data(domain: str, api_key: str) -> dict:
    """
    Accepts a domain and VirusTotal API key.
    Returns structured detection counts, vendor flags, and reputation data.
    """

    headers = {
        "x-apikey": api_key,
        "Accept":   "application/json",
    }

    url = f"{VT_API}/domains/{domain}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}", "domain": domain}

    if resp.status_code == 401:
        return {"error": "Invalid VirusTotal API key.", "domain": domain}
    if resp.status_code == 404:
        return {"error": "Domain not found in VirusTotal.", "domain": domain}
    if resp.status_code == 429:
        return {"error": "Rate limited by VirusTotal. Wait before retrying.", "domain": domain}
    if resp.status_code != 200:
        return {"error": f"VirusTotal API returned {resp.status_code}", "domain": domain}

    data = resp.json().get("data", {}).get("attributes", {})

    # ── Extract analysis stats ────────────────────────────────────────
    stats      = data.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected

    # ── Collect vendor names that flagged the domain ──────────────────
    analysis_results = data.get("last_analysis_results", {})
    flagging_vendors = [
        vendor for vendor, res in analysis_results.items()
        if res.get("category") in ("malicious", "suspicious")
    ]

    result = {
        "domain":                domain,
        "reputation_score":      data.get("reputation", 0),
        "malicious_detections":  malicious,
        "suspicious_detections": suspicious,
        "harmless_detections":   harmless,
        "total_engines":         total_engines,
        "flagging_vendors":      flagging_vendors,
        "total_flagging":        len(flagging_vendors),
        "categories":            data.get("categories", {}),
        "popularity_ranks":      data.get("popularity_ranks", {}),
        "last_analysis_date":    data.get("last_analysis_date", ""),
        "tags":                  data.get("tags", []),
        "is_malicious":          malicious > 0,
        "is_suspicious":         malicious > 0 or suspicious > 2,
    }

    return result

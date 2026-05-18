"""
shodan_lookup.py
----------------
Resolves a domain to its IP address and queries the Shodan API
for open ports, running services, and banner data relevant to
threat intelligence analysis.

Requires a Shodan API key. Free keys are available at:
https://account.shodan.io/register

Note: Each host lookup costs 1 Shodan query credit.
Free-tier accounts have limited credits per month.
"""

import socket
import shodan


def get_shodan_data(domain: str, api_key: str) -> dict:
    """
    Accepts a domain and Shodan API key.
    Resolves the domain to an IP, then queries Shodan for that host.
    Returns a structured dict of port, service, and vulnerability data.
    """

    # ── Step 1: Resolve domain to IP ─────────────────────────────────
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {"error": f"DNS resolution failed: {str(e)}", "domain": domain}

    # ── Step 2: Query Shodan for that IP ─────────────────────────────
    api = shodan.Shodan(api_key)

    try:
        host = api.host(ip)
    except shodan.APIError as e:
        return {"error": f"Shodan API error: {str(e)}", "domain": domain, "ip": ip}

    # ── Step 3: Extract TI-relevant service data ──────────────────────
    services = []
    for item in host.get("data", []):
        services.append({
            "port":      item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product":   item.get("product", "Unknown"),
            "version":   item.get("version", ""),
            "cpe":       item.get("cpe", []),
            "vulns":     list(item.get("vulns", {}).keys()),  # CVE IDs Shodan detected
            "timestamp": item.get("timestamp", "")[:10],
        })

    # ── Step 4: Flag notable open ports ──────────────────────────────
    # Ports commonly associated with risky or misconfigured exposure
    sensitive_ports = {21, 22, 23, 25, 445, 3389, 5900, 6379, 9200, 27017}
    flagged_ports = [s["port"] for s in services if s["port"] in sensitive_ports]

    all_vulns = list({v for s in services for v in s["vulns"]})

    result = {
        "domain":         domain,
        "ip":             ip,
        "hostnames":      host.get("hostnames", []),
        "org":            host.get("org", "Not available"),
        "isp":            host.get("isp", "Not available"),
        "asn":            host.get("asn", "Not available"),
        "country":        host.get("country_name", "Not available"),
        "city":           host.get("city", "Not available"),
        "open_ports":     host.get("ports", []),
        "total_services": len(services),
        "services":       services,
        "flagged_ports":  flagged_ports,
        "cves_detected":  all_vulns,
        "total_cves":     len(all_vulns),
        "last_updated":   host.get("last_update", "")[:10],
    }

    return result

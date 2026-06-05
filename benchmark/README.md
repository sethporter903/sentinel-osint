# SentinelOSINT Benchmark Evaluation

This directory contains an independent accuracy evaluation of SentinelOSINT against a curated ground truth dataset of known-benign and known-malicious IP addresses.

---

## Dataset

The dataset is stored in [`ground_truth.json`](ground_truth.json) and contains **40 IP addresses** split evenly between two classes:

| Class | Count | Description |
|-------|-------|-------------|
| Benign | 20 | Public DNS resolvers, CDN infrastructure, major cloud providers |
| Malicious | 20 | Documented botnet C2 servers, high-abuse IPs from public threat intel feeds |

### Benign IP Sources

Benign IPs were selected from well-known, publicly documented infrastructure operated by trusted organizations. Selection criteria:

- Officially documented by the operator (e.g., Google's 8.8.8.8 DNS documentation)
- Listed on GreyNoise RIOT (Reliable Intelligence on IPs Observed in Threat data) as known benign services
- ASN attribution to a recognizable, publicly traded company (Google, Cloudflare, Meta, Amazon, Fastly, Twitter/X)

**Included providers:** Google Public DNS, Cloudflare DNS, Quad9, Cisco OpenDNS, Cloudflare CDN, Fastly CDN, Amazon CloudFront, Amazon Route 53, Google web infrastructure, Meta Platforms, Twitter/X Corp

### Malicious IP Sources

Malicious IPs were sourced exclusively from public threat intelligence feeds with a documented history of reliability:

| Feed | URL | Description |
|------|-----|-------------|
| **Feodo Tracker** | [abuse.ch/feodotracker](https://abuse.ch/feodotracker/) | Botnet C2 servers (Emotet, TrickBot, Dridex, QakBot) |
| **AbuseIPDB** | [abuseipdb.com](https://www.abuseipdb.com/) | Community-reported attack IPs; entries selected with high confidence scores |
| **Spamhaus** | [spamhaus.org](https://www.spamhaus.org/) | ZEN blocklist, CBL (Composite Blocking List) |
| **AlienVault OTX** | [otx.alienvault.com](https://otx.alienvault.com/) | Cross-referenced as corroborating evidence |

Selection criteria for malicious IPs:

- Present on at least one authoritative blocklist (Feodo Tracker, Spamhaus ZEN, or AbuseIPDB with high confidence)
- Multiple independent feed corroboration preferred where possible
- Includes a mix of: botnet C2 infrastructure, high-volume scanning/brute-force IPs, and Tor exit nodes associated with malicious traffic

**A note on Tor exit nodes:** Several malicious entries are Tor exit nodes (e.g., `185.220.101.47`, `185.220.100.240`, `162.247.74.7`, `192.42.116.27`, `171.25.193.20`). Tor exit nodes present a genuine classification challenge: the IP itself is not intrinsically malicious, but the traffic relayed through it frequently is, and they appear prominently on threat intel blocklists. Their classification as "malicious" in this benchmark reflects their standing in public threat intelligence feeds — the same feeds that SentinelOSINT queries — which is the operationally relevant signal for defenders.

---

## Methodology

### Analysis Pipeline

Each target is submitted to the SentinelOSINT `/api/analyze` endpoint, which fans out to **11 concurrent intelligence sources**:

1. WHOIS / RDAP (IP registration, ASN, country)
2. AlienVault OTX (threat pulses, malware families)
3. GreyNoise (mass-scanner detection, RIOT benign-service list)
4. AbuseIPDB (community abuse reports, confidence score)
5. Shodan (open ports, service banners, CVEs)
6. MalwareBazaar (hash-based malware database)
7. URLhaus (malicious URL/domain database)
8. CIRCL Passive DNS (historical DNS resolutions)
9. VirusTotal Passive DNS (DNS resolution history)
10. GitHub (public repository mentions)
11. ThreatFox (IOC database with threat actor attribution)

Source data is then synthesized by a **Claude LLM** (claude-sonnet-4-5) using a structured system prompt that encodes threat intelligence interpretation rules. The LLM produces a final report with:

```json
{
  "verdict": "malicious | suspicious | benign | unknown",
  "overall_confidence": 0-100,
  "summary": "Plain English assessment",
  "key_findings": ["..."],
  "mitre_techniques": [{"technique_id": "...", "technique_name": "...", "justification": "..."}],
  "tlp": "WHITE | GREEN | AMBER"
}
```

### Classification Thresholds

The benchmark script evaluates accuracy under two binary classification thresholds:

| Threshold | Positive Prediction | Negative Prediction |
|-----------|--------------------|--------------------|
| **Lenient** (default) | `malicious` or `suspicious` | `benign` or `unknown` |
| **Strict** (`--strict` flag) | `malicious` only | `suspicious`, `benign`, or `unknown` |

The lenient threshold reflects operational reality: a SOC analyst should act on a "suspicious" verdict. The strict threshold evaluates whether the tool achieves high-confidence malicious classification.

### Metrics Computed

| Metric | Formula | Interpretation |
|--------|---------|---------------|
| **Precision** | TP / (TP + FP) | Of IPs flagged as malicious, what fraction actually are? |
| **Recall (TPR)** | TP / (TP + FN) | Of actually malicious IPs, what fraction did the tool catch? |
| **False Positive Rate** | FP / (FP + TN) | Of actually benign IPs, what fraction were incorrectly flagged? |
| **False Negative Rate** | FN / (FN + TP) | Of actually malicious IPs, what fraction were missed? |
| **F1 Score** | 2·P·R / (P + R) | Harmonic mean of precision and recall |
| **Accuracy** | (TP + TN) / total | Overall correct classification rate |

---

## Running the Benchmark

### Prerequisites

```bash
# Install benchmark dependency
pip install httpx

# Start the SentinelOSINT backend (from project root)
cd backend
pip install -r requirements.txt
cp ../.env.example .env   # then fill in your API keys
uvicorn main:app --reload
```

### Basic run (all 40 targets, lenient threshold)

```bash
python benchmark/run_benchmark.py
```

### Custom options

```bash
# Strict mode: only "malicious" verdict counts as a positive prediction
python benchmark/run_benchmark.py --strict

# Custom API URL (e.g., production deployment)
python benchmark/run_benchmark.py --api-url https://your-deployment.example.com/api

# Slower request rate to avoid hitting source API rate limits
python benchmark/run_benchmark.py --delay 5

# Run only a subset of targets
python benchmark/run_benchmark.py --targets "8.8.8.8,1.1.1.1,185.220.101.47"

# Save results to a custom path
python benchmark/run_benchmark.py --output my_results.json
```

### Estimated runtime

With the default 2-second delay and 40 targets, each requiring ~10–30 seconds of concurrent API calls plus LLM synthesis, a full benchmark run takes approximately **15–25 minutes**. Increase `--delay` if you observe rate-limit errors from AbuseIPDB, VirusTotal, or OTX.

---

## Results

Results are saved to [`results.json`](results.json) after each run. The file contains:

```json
{
  "run_timestamp": "2025-01-01T00:00:00+00:00",
  "api_url": "http://localhost:8000/api",
  "total_targets": 40,
  "metrics": {
    "lenient_threshold": {
      "precision": 0.0,
      "recall": 0.0,
      "false_positive_rate": 0.0,
      "false_negative_rate": 0.0,
      "f1_score": 0.0,
      "accuracy": 0.0,
      "true_positives": 0,
      "false_positives": 0,
      "true_negatives": 0,
      "false_negatives": 0
    },
    "strict_threshold": { "..." : "..." }
  },
  "results": [
    {
      "target": "8.8.8.8",
      "ground_truth": "benign",
      "source": "Google Public DNS — ...",
      "tool_verdict": "benign",
      "tool_confidence": 95,
      "tool_summary": "...",
      "key_findings": ["..."]
    }
  ]
}
```

*Note: `results.json` is git-ignored because it contains live API response data that varies with API key access and source availability. Run the benchmark locally to generate your own results file.*

---

## Limitations & Known Caveats

### Dataset size
With 40 targets, confidence intervals on the metrics are wide. A ±10% swing in any metric can be caused by 4 classification errors. This dataset is suitable for a directional accuracy signal, not a statistically rigorous evaluation.

### IP address stability
IP addresses can be reassigned after a threat actor's infrastructure is taken down. A malicious IP that appeared on Feodo Tracker in 2023 may now serve legitimate traffic. Similarly, CDN IPs rotate. The dataset was assembled from authoritative sources and reflects ground truth at the time of creation; re-running the benchmark months later may produce different results if IPs have been reassigned.

### API key coverage
Results vary significantly based on which API keys are configured. A deployment without an AbuseIPDB key will miss one of the strongest signals for several malicious IPs. The benchmark assumes full API key coverage for meaningful results.

### LLM non-determinism
The LLM synthesis step is non-deterministic; the same input can occasionally yield different verdicts across runs. Running the benchmark multiple times and averaging results would give a more stable estimate.

### Tor exit node ambiguity
Five malicious entries are Tor exit nodes. Some security tools classify these as "suspicious" rather than "malicious" because the infrastructure itself is neutral (privacy tool), even though the traffic passing through is frequently malicious. Under the lenient threshold this distinction does not affect the result, but under strict mode these may show as false negatives.

---

## Dataset Sources

- **Feodo Tracker:** https://feodotracker.abuse.ch — botnet C2 blocklist, updated continuously by abuse.ch
- **AbuseIPDB:** https://www.abuseipdb.com — community IP abuse reports with confidence scoring
- **Spamhaus ZEN/CBL:** https://www.spamhaus.org/blocklists — spam and malware IP blocklists
- **AlienVault OTX:** https://otx.alienvault.com — open threat exchange, community threat intel pulses
- **GreyNoise RIOT:** https://www.greynoise.io/blog/greynoise-riot — reliable intelligence on benign IP infrastructure
- **Google Public DNS documentation:** https://developers.google.com/speed/public-dns
- **Cloudflare 1.1.1.1 documentation:** https://cloudflare.com/learning/dns/what-is-1.1.1.1
- **Quad9 documentation:** https://www.quad9.net

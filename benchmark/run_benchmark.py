#!/usr/bin/env python3
"""
SentinelOSINT Benchmark Runner

Evaluates SentinelOSINT's classification accuracy against a ground truth dataset
of 20 known-benign and 20 known-malicious IP addresses. Outputs precision, recall,
false positive rate, false negative rate, and a full per-target results report.

Usage:
    python benchmark/run_benchmark.py [options]

Options:
    --api-url URL     Base URL of the SentinelOSINT API  (default: http://localhost:8000/api)
    --delay SECS      Seconds between requests to respect API rate limits (default: 2)
    --strict          Only count verdict "malicious" as a positive prediction;
                      by default "suspicious" is also treated as a positive
    --output PATH     Path to save the JSON results report (default: benchmark/results.json)
    --targets SUBSET  Comma-separated list of IPs to run (default: all 40 targets)

Requirements:
    pip install httpx
    The SentinelOSINT backend must be running:
        cd backend && uvicorn main:app --reload
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import httpx
except ImportError:
    print("ERROR: httpx is not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(1)


BENCHMARK_DIR = Path(__file__).parent
GROUND_TRUTH_FILE = BENCHMARK_DIR / "ground_truth.json"
DEFAULT_OUTPUT = BENCHMARK_DIR / "results.json"


# ── Data loading ──────────────────────────────────────────────────────────────

def load_ground_truth(target_filter: list[str] | None = None) -> list[dict]:
    """Load and flatten the ground truth dataset into a list of entries."""
    with open(GROUND_TRUTH_FILE, encoding="utf-8") as f:
        data = json.load(f)

    entries = []
    for items in (data.get("benign", []), data.get("malicious", [])):
        for item in items:
            entry = {
                "target": item["target"],
                "ground_truth": item["ground_truth"],
                "source": item["source"],
            }
            if target_filter is None or entry["target"] in target_filter:
                entries.append(entry)
    return entries


# ── API interaction ───────────────────────────────────────────────────────────

def analyze_target(client: httpx.Client, api_url: str, target: str) -> dict:
    """Call the /analyze endpoint for a single target. Returns the raw JSON response."""
    try:
        resp = client.get(
            f"{api_url}/analyze",
            params={"target": target},
            timeout=120.0,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.TimeoutException:
        return {"error": "timeout", "target": target}
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}", "target": target}
    except Exception as e:
        return {"error": str(e), "target": target}


def extract_verdict(response: dict) -> str:
    """Pull the verdict string out of an API response dict."""
    if "error" in response and "report" not in response:
        return "error"
    report = response.get("report", {})
    if isinstance(report, dict):
        return report.get("verdict", "unknown").lower()
    return "unknown"


def extract_confidence(response: dict) -> int | None:
    """Pull overall confidence score (0-100) from the report, if present."""
    report = response.get("report", {})
    if not isinstance(report, dict):
        return None
    for key in ("overall_confidence", "llm_confidence", "source_confidence"):
        val = report.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
    return None


# ── Classification & metrics ──────────────────────────────────────────────────

def verdict_to_binary(verdict: str, strict: bool) -> str:
    """
    Map a tool verdict to a binary 'malicious' / 'benign' prediction.

    Strict mode  → only "malicious" is treated as positive.
    Default mode → "malicious" OR "suspicious" is treated as positive.
    """
    if strict:
        return "malicious" if verdict == "malicious" else "benign"
    return "malicious" if verdict in ("malicious", "suspicious") else "benign"


def compute_metrics(results: list[dict], strict: bool) -> dict:
    """Compute binary classification metrics from the per-target results list."""
    tp = fp = tn = fn = errors = 0

    for r in results:
        gt = r["ground_truth"]
        verdict = r.get("tool_verdict", "error")

        if verdict == "error":
            errors += 1
            continue

        predicted = verdict_to_binary(verdict, strict=strict)

        if gt == "malicious" and predicted == "malicious":
            tp += 1
        elif gt == "benign" and predicted == "malicious":
            fp += 1
        elif gt == "benign" and predicted == "benign":
            tn += 1
        else:  # gt == "malicious" and predicted == "benign"
            fn += 1

    total_scored = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr       = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (tp + tn) / total_scored if total_scored > 0 else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "errors_excluded": errors,
        "total_evaluated": total_scored,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_summary(results: list[dict], metrics: dict, strict: bool) -> None:
    threshold = "malicious only" if strict else "malicious + suspicious"
    width = 72

    print("\n" + "=" * width)
    print("  SentinelOSINT Benchmark Results")
    print(f"  Positive threshold : {threshold}")
    print("=" * width)

    header = f"  {'Target':<20} {'Ground Truth':<14} {'Tool Verdict':<14} {'Match':6} {'Conf':>5}"
    print(f"\n{header}")
    print("  " + "-" * (width - 2))

    for r in results:
        gt      = r["ground_truth"]
        verdict = r.get("tool_verdict", "error")
        conf    = r.get("tool_confidence")
        conf_s  = f"{conf}%" if isinstance(conf, int) else "  n/a"

        if verdict == "error":
            match_s = "ERROR"
        else:
            predicted = verdict_to_binary(verdict, strict=strict)
            match_s = "  OK" if predicted == gt else "FAIL"

        print(f"  {r['target']:<20} {gt:<14} {verdict:<14} {match_s:6} {conf_s:>5}")

    print()
    print("=" * width)
    print("  Metrics")
    print("=" * width)
    print(f"  Accuracy            : {metrics['accuracy']:.1%}")
    print(f"  Precision           : {metrics['precision']:.1%}")
    print(f"  Recall (TPR)        : {metrics['recall']:.1%}")
    print(f"  False Positive Rate : {metrics['false_positive_rate']:.1%}")
    print(f"  False Negative Rate : {metrics['false_negative_rate']:.1%}")
    print(f"  F1 Score            : {metrics['f1_score']:.4f}")
    print()
    print(f"  TP={metrics['true_positives']}  "
          f"TN={metrics['true_negatives']}  "
          f"FP={metrics['false_positives']}  "
          f"FN={metrics['false_negatives']}", end="")
    if metrics["errors_excluded"] > 0:
        print(f"  ({metrics['errors_excluded']} errors excluded from metrics)", end="")
    print()
    print("=" * width)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate SentinelOSINT accuracy against a ground truth dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000/api",
        help="SentinelOSINT API base URL (default: http://localhost:8000/api)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Seconds between requests (default: 2); increase if hitting rate limits",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Only count 'malicious' verdict as positive; by default 'suspicious' also counts",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output JSON file path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--targets",
        help="Comma-separated list of IPs to run (default: all targets in ground_truth.json)",
    )
    args = parser.parse_args()

    target_filter = (
        [t.strip() for t in args.targets.split(",")]
        if args.targets else None
    )

    print(f"Loading ground truth: {GROUND_TRUTH_FILE}")
    entries = load_ground_truth(target_filter=target_filter)
    if not entries:
        print("ERROR: No matching targets found in ground_truth.json.", file=sys.stderr)
        sys.exit(1)

    benign_count    = sum(1 for e in entries if e["ground_truth"] == "benign")
    malicious_count = sum(1 for e in entries if e["ground_truth"] == "malicious")
    print(f"Targets: {len(entries)} total  ({benign_count} benign / {malicious_count} malicious)")
    print(f"API URL: {args.api_url}")
    print(f"Delay  : {args.delay}s between requests")
    threshold_label = "malicious only" if args.strict else "malicious + suspicious"
    print(f"Positive threshold: {threshold_label}")

    results: list[dict] = []

    with httpx.Client() as client:
        # Confirm the API is up before starting.
        print("\nChecking API availability...", end=" ", flush=True)
        try:
            health = client.get(f"{args.api_url}/", timeout=10.0)
            health.raise_for_status()
            print("OK")
        except Exception as e:
            print(f"FAILED\n\nERROR: Cannot reach {args.api_url}: {e}")
            print("Start the backend with:  cd backend && uvicorn main:app --reload")
            sys.exit(1)

        print(f"\nRunning {len(entries)} analyses...\n")

        for i, entry in enumerate(entries, 1):
            target = entry["target"]
            gt     = entry["ground_truth"]
            print(
                f"[{i:>2}/{len(entries)}] {target:<20} (truth: {gt:<9}) ...",
                end=" ",
                flush=True,
            )

            response = analyze_target(client, args.api_url, target)
            verdict  = extract_verdict(response)
            conf     = extract_confidence(response)
            report   = response.get("report", {}) if isinstance(response.get("report"), dict) else {}

            result = {
                **entry,
                "tool_verdict": verdict,
                "tool_confidence": conf,
                "tool_summary": report.get("summary", ""),
                "key_findings": report.get("key_findings", []),
                "mitre_techniques": report.get("mitre_techniques", []),
                "error": response.get("error"),
            }
            results.append(result)

            if verdict == "error":
                print(f"→ ERROR ({response.get('error', 'unknown')})")
            else:
                predicted   = verdict_to_binary(verdict, strict=args.strict)
                match_label = "OK" if predicted == gt else "FAIL"
                conf_label  = f" ({conf}% confidence)" if conf is not None else ""
                print(f"→ {verdict}{conf_label}  [{match_label}]")

            if i < len(entries):
                time.sleep(args.delay)

    # Compute metrics for both thresholds so both appear in the JSON report.
    lenient_metrics = compute_metrics(results, strict=False)
    strict_metrics  = compute_metrics(results, strict=True)

    # Print the summary using whichever threshold was selected.
    active_metrics = strict_metrics if args.strict else lenient_metrics
    print_summary(results, active_metrics, strict=args.strict)

    # Persist the full report.
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report_data = {
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "api_url": args.api_url,
        "total_targets": len(entries),
        "positive_threshold_used": "strict (malicious only)" if args.strict else "lenient (malicious + suspicious)",
        "metrics": {
            "lenient_threshold": {
                "description": "malicious + suspicious verdicts count as positive",
                **lenient_metrics,
            },
            "strict_threshold": {
                "description": "only malicious verdict counts as positive",
                **strict_metrics,
            },
        },
        "results": results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    print(f"\nFull results saved to: {output_path}")


if __name__ == "__main__":
    main()

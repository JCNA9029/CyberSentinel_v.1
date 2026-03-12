# eval_harness.py — CyberSentinel Evaluation & Benchmarking Harness
#
# Measures Tier 2 (ML) and optionally Tier 1 (Cloud) detection performance
# against a labelled sample set. Outputs metrics to terminal and eval_report.json.
#
# Usage:
#   python eval_harness.py --malware ./samples/malware --clean ./samples/clean
#   python eval_harness.py --malware ./samples/malware --clean ./samples/clean --tier1
#
# Sample directory layout:
#   samples/
#     malware/   ← known-malicious PE files (ground truth: positive)
#     clean/     ← known-clean PE files     (ground truth: negative)

import argparse
import os
import sys
import time
import json
import datetime

# Allow importing from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.ml_engine import LocalScanner
from modules import utils

# ─────────────────────────────────────────────
#  TIER 2 (ML) EVALUATION
# ─────────────────────────────────────────────

def evaluate_tier2(malware_dir: str, clean_dir: str) -> dict:
    """Runs Tier 2 ML inference on labelled samples and returns metric counts."""
    scanner = LocalScanner()
    utils.init_db()

    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "errors": 0}
    latencies: list[float] = []
    misses: list[str] = []
    false_alarms: list[str] = []

    def scan(file_path: str, expected_malicious: bool):
        t0 = time.perf_counter()
        result = scanner.scan_stage1(file_path)
        latencies.append(time.perf_counter() - t0)

        if result is None:
            counts["errors"] += 1
            return

        detected = result["is_malicious"]
        score    = result["score"]
        name     = os.path.basename(file_path)

        if expected_malicious and detected:
            counts["TP"] += 1
        elif expected_malicious and not detected:
            counts["FN"] += 1
            misses.append(f"{name} (score={score:.4f})")
        elif not expected_malicious and detected:
            counts["FP"] += 1
            false_alarms.append(f"{name} (score={score:.4f})")
        else:
            counts["TN"] += 1

    print(f"\n[*] Scanning malware samples: {malware_dir}")
    for f in sorted(os.listdir(malware_dir)):
        fp = os.path.join(malware_dir, f)
        if os.path.isfile(fp):
            scan(fp, expected_malicious=True)

    print(f"[*] Scanning clean samples:   {clean_dir}")
    for f in sorted(os.listdir(clean_dir)):
        fp = os.path.join(clean_dir, f)
        if os.path.isfile(fp):
            scan(fp, expected_malicious=False)

    return {"counts": counts, "latencies": latencies, "misses": misses, "false_alarms": false_alarms}


# ─────────────────────────────────────────────
#  TIER 1 (CLOUD) EVALUATION
# ─────────────────────────────────────────────

def evaluate_tier1(malware_dir: str, clean_dir: str, logic) -> dict:
    """Runs Tier 1 concurrent cloud consensus on labelled samples."""
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "errors": 0}
    latencies: list[float] = []

    def scan_hash(file_path: str, expected_malicious: bool):
        sha = utils.get_sha256(file_path)
        if not sha:
            counts["errors"] += 1
            return
        t0 = time.perf_counter()
        result = logic._run_tier1_concurrent(sha)
        latencies.append(time.perf_counter() - t0)

        detected = result["verdict"] == "MALICIOUS"
        if expected_malicious and detected:     counts["TP"] += 1
        elif expected_malicious and not detected: counts["FN"] += 1
        elif not expected_malicious and detected: counts["FP"] += 1
        else:                                     counts["TN"] += 1

    print(f"\n[*] Tier 1 — scanning malware hashes...")
    for f in sorted(os.listdir(malware_dir)):
        fp = os.path.join(malware_dir, f)
        if os.path.isfile(fp):
            scan_hash(fp, expected_malicious=True)

    print(f"[*] Tier 1 — scanning clean hashes...")
    for f in sorted(os.listdir(clean_dir)):
        fp = os.path.join(clean_dir, f)
        if os.path.isfile(fp):
            scan_hash(fp, expected_malicious=False)

    return {"counts": counts, "latencies": latencies}


# ─────────────────────────────────────────────
#  METRICS COMPUTATION
# ─────────────────────────────────────────────

def compute_metrics(counts: dict, latencies: list) -> dict:
    TP, FP, TN, FN = counts["TP"], counts["FP"], counts["TN"], counts["FN"]
    total = TP + FP + TN + FN

    dr        = TP / (TP + FN) if (TP + FN) > 0 else 0.0   # Detection Rate (Recall)
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0   # False Positive Rate
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    f1        = 2 * precision * dr / (precision + dr) if (precision + dr) > 0 else 0.0
    accuracy  = (TP + TN) / total if total > 0 else 0.0
    avg_lat   = (sum(latencies) / len(latencies) * 1000) if latencies else 0.0

    return {
        "total_samples":     total,
        "detection_rate":    round(dr, 4),
        "false_positive_rate": round(fpr, 4),
        "precision":         round(precision, 4),
        "f1_score":          round(f1, 4),
        "accuracy":          round(accuracy, 4),
        "avg_latency_ms":    round(avg_lat, 2),
        "counts":            counts,
    }


# ─────────────────────────────────────────────
#  REPORT OUTPUT
# ─────────────────────────────────────────────

def print_report(tier_name: str, metrics: dict, misses: list = None, false_alarms: list = None):
    c = metrics["counts"]
    print(f"\n{'='*60}")
    print(f"  CYBERSENTINEL EVALUATION — {tier_name}")
    print(f"{'='*60}")
    print(f"  Total Samples    : {metrics['total_samples']}")
    print(f"  True Positives   : {c['TP']}")
    print(f"  False Positives  : {c['FP']}")
    print(f"  True Negatives   : {c['TN']}")
    print(f"  False Negatives  : {c['FN']}")
    print(f"  Scan Errors      : {c['errors']}")
    print(f"{'─'*60}")
    print(f"  Detection Rate   : {metrics['detection_rate']:.2%}")
    print(f"  False Pos. Rate  : {metrics['false_positive_rate']:.2%}")
    print(f"  Precision        : {metrics['precision']:.2%}")
    print(f"  F1 Score         : {metrics['f1_score']:.4f}")
    print(f"  Accuracy         : {metrics['accuracy']:.2%}")
    print(f"  Avg Latency/file : {metrics['avg_latency_ms']:.1f} ms")
    print(f"{'='*60}")

    if misses:
        print(f"\n  False Negatives (missed malware):")
        for m in misses[:10]:
            print(f"    ✗ {m}")
        if len(misses) > 10:
            print(f"    ... and {len(misses)-10} more")

    if false_alarms:
        print(f"\n  False Positives (clean files flagged):")
        for fa in false_alarms[:10]:
            print(f"    ✗ {fa}")
        if len(false_alarms) > 10:
            print(f"    ... and {len(false_alarms)-10} more")


def save_report(report_data: dict, output_path: str = "eval_report.json"):
    try:
        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[+] Full report saved: {os.path.abspath(output_path)}")
    except Exception as e:
        print(f"[-] Could not save report: {e}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberSentinel Evaluation Harness")
    parser.add_argument("--malware", required=True, metavar="DIR", help="Directory of known-malicious PE samples.")
    parser.add_argument("--clean",   required=True, metavar="DIR", help="Directory of known-clean PE samples.")
    parser.add_argument("--tier1",   action="store_true",          help="Also evaluate Tier 1 cloud consensus.")
    parser.add_argument("--output",  default="eval_report.json",   help="Output JSON file path.")
    args = parser.parse_args()

    if not os.path.isdir(args.malware):
        print(f"[-] Malware directory not found: {args.malware}")
        sys.exit(1)
    if not os.path.isdir(args.clean):
        print(f"[-] Clean directory not found: {args.clean}")
        sys.exit(1)

    full_report = {
        "generated": datetime.datetime.now().isoformat(),
        "malware_dir": os.path.abspath(args.malware),
        "clean_dir":   os.path.abspath(args.clean),
    }

    # ── Tier 2 ──────────────────────────────────────────────────────────────
    t2_raw = evaluate_tier2(args.malware, args.clean)
    t2_metrics = compute_metrics(t2_raw["counts"], t2_raw["latencies"])
    print_report("TIER 2: Local ML Engine", t2_metrics, t2_raw["misses"], t2_raw["false_alarms"])
    full_report["tier2"] = t2_metrics

    # ── Tier 1 (optional) ───────────────────────────────────────────────────
    if args.tier1:
        from modules.analysis_manager import ScannerLogic
        logic = ScannerLogic()
        if not logic.api_keys:
            print("\n[!] Tier 1 skipped: no API keys configured. Run CyberSentinel.py option 5 first.")
        else:
            t1_raw = evaluate_tier1(args.malware, args.clean, logic)
            t1_metrics = compute_metrics(t1_raw["counts"], t1_raw["latencies"])
            print_report("TIER 1: Cloud Consensus", t1_metrics)
            full_report["tier1"] = t1_metrics

    save_report(full_report, args.output)


if __name__ == "__main__":
    main()

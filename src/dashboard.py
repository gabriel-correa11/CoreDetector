import csv
import json
import os
import re
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "api_audit.log")
FEEDBACK_PATH = os.path.join(PROJECT_ROOT, "data", "feedback.csv")
REGISTRY_PATH = os.path.join(PROJECT_ROOT, "models", "registry.json")

_LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ - \w+ - "
    r"(?:WhatsApp \| )?Hash: \w+ \| Score: ([\d.]+) \| Fraud: (True|False)"
)
_LATENCY_RE = re.compile(r"Latency: ([\d.]+)ms")
_FALSE_POSITIVE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ - WARNING - False positive reported"
)


def _parse_log(hours: int = 24) -> Dict:
    cutoff = datetime.now() - timedelta(hours=hours)
    scores: List[float] = []
    latencies: List[float] = []
    fraud_count = 0
    false_positive_count = 0

    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                fp_match = _FALSE_POSITIVE_RE.match(line)
                if fp_match:
                    ts = datetime.strptime(fp_match.group(1), "%Y-%m-%d %H:%M:%S")
                    if ts >= cutoff:
                        false_positive_count += 1
                    continue

                m = _LOG_LINE_RE.match(line)
                if not m:
                    continue

                ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                if ts < cutoff:
                    continue

                scores.append(float(m.group(2)))
                if m.group(3) == "True":
                    fraud_count += 1

                lat_match = _LATENCY_RE.search(line)
                if lat_match:
                    latencies.append(float(lat_match.group(1)))
    except FileNotFoundError:
        pass

    total = len(scores)
    legit_count = total - fraud_count

    score_stats: Dict = {
        "avg": round(statistics.mean(scores), 4) if scores else 0.0,
        "min": round(min(scores), 4) if scores else 0.0,
        "max": round(max(scores), 4) if scores else 0.0,
    }

    if latencies:
        sorted_lat = sorted(latencies)
        p95_idx = max(0, int(len(sorted_lat) * 0.95) - 1)
        latency_stats: Dict = {
            "avg_ms": round(statistics.mean(latencies), 2),
            "p95_ms": round(sorted_lat[p95_idx], 2),
            "max_ms": round(max(latencies), 2),
        }
    else:
        latency_stats = {"avg_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}

    return {
        "total_requests": total,
        "fraud_count": fraud_count,
        "legit_count": legit_count,
        "fraud_rate": round(fraud_count / total, 4) if total else 0.0,
        "risk_score": score_stats,
        "latency": latency_stats,
        "false_positives_reported": false_positive_count,
    }


def _parse_feedback() -> Dict:
    total = 0
    fraud_count = 0

    try:
        with open(FEEDBACK_PATH, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) < 2:
                    continue
                try:
                    label = int(row[1])
                    total += 1
                    if label == 1:
                        fraud_count += 1
                except ValueError:
                    continue
    except FileNotFoundError:
        pass

    return {
        "total_feedback": total,
        "fraud_labeled": fraud_count,
        "legit_labeled": total - fraud_count,
    }


def _get_production_model() -> Dict:
    try:
        with open(REGISTRY_PATH, "r") as f:
            registry = json.load(f)
        prod: Optional[Dict] = next(
            (m for m in registry if m["status"] == "production"), None
        )
        if prod:
            return {"version": prod["version"], "metrics": prod["metrics"]}
    except (FileNotFoundError, StopIteration, KeyError):
        pass
    return {}


def get_dashboard(hours: int = 24) -> Dict:
    log_stats = _parse_log(hours)
    return {
        "window_hours": hours,
        "generated_at": datetime.now().isoformat(),
        **log_stats,
        "feedback": _parse_feedback(),
        "production_model": _get_production_model(),
    }

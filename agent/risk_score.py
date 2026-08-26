"""
CyberForge Risk Scoring Engine

Computes a numeric risk score from evidence indicators gathered by
the MCP investigation tools. Designed to run in Code Mode as a
sandbox subagent — receives merged findings, returns a score.

Thresholds:
  0–29   LOW
  30–59  MEDIUM
  60–79  HIGH
  80–100 CRITICAL
"""

import json
import sys
from pathlib import Path

# Scoring weights — each indicator contributes a fixed point value.
WEIGHTS = {
    "failed_attempts": 20,       # ≥20 failed SSH auth attempts
    "successful_suspicious_login": 25,  # successful login after brute force
    "suspicious_process": 25,    # suspicious process running on host
    "unusual_connection": 20,    # unusual network connection (e.g. port 4444)
    "known_bad_source": 10,      # source IP on a known-bad list
}

THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
]


def compute_risk_score(risk_indicators: dict, known_bad_ips: list[str] | None = None) -> dict:
    """
    Compute a risk score from evidence indicators.

    Args:
        risk_indicators: dict with boolean/numeric indicator values
            from analyze_evidence output.
        known_bad_ips: optional list of IPs to check against.

    Returns:
        dict with score, level, and per-indicator breakdown.
    """
    known_bad_ips = known_bad_ips or ["10.0.0.25"]
    breakdown = {}
    score = 0

    # Failed attempts: +20 if there were any (threshold is ≥20 in the data)
    if risk_indicators.get("failed_attempts", 0) >= 20:
        pts = WEIGHTS["failed_attempts"]
        score += pts
        breakdown["failed_attempts"] = {"points": pts, "reason": f"{risk_indicators['failed_attempts']} failed attempts (≥20)"}
    else:
        breakdown["failed_attempts"] = {"points": 0, "reason": "Below threshold (<20 failed attempts)"}

    # Successful suspicious login: +25
    if risk_indicators.get("successful_suspicious_login", False):
        pts = WEIGHTS["successful_suspicious_login"]
        score += pts
        breakdown["successful_suspicious_login"] = {"points": pts, "reason": "Successful login detected after repeated failures"}
    else:
        breakdown["successful_suspicious_login"] = {"points": 0, "reason": "No suspicious successful login"}

    # Suspicious process: +25
    if risk_indicators.get("suspicious_process", False):
        pts = WEIGHTS["suspicious_process"]
        score += pts
        breakdown["suspicious_process"] = {"points": pts, "reason": "Suspicious process detected on host"}
    else:
        breakdown["suspicious_process"] = {"points": 0, "reason": "No suspicious process detected"}

    # Unusual connection: +20
    if risk_indicators.get("unusual_connection", False):
        pts = WEIGHTS["unusual_connection"]
        score += pts
        breakdown["unusual_connection"] = {"points": pts, "reason": "Unusual network connection detected"}
    else:
        breakdown["unusual_connection"] = {"points": 0, "reason": "No unusual connections detected"}

    # Known-bad source IP: +10
    source_ip = risk_indicators.get("source_ip", "")
    if source_ip in known_bad_ips:
        pts = WEIGHTS["known_bad_source"]
        score += pts
        breakdown["known_bad_source"] = {"points": pts, "reason": f"Source IP {source_ip} is on known-bad list"}
    else:
        breakdown["known_bad_source"] = {"points": 0, "reason": "Source IP not on known-bad list"}

    # Determine level
    level = "LOW"
    for threshold, label in THRESHOLDS:
        if score >= threshold:
            level = label
            break

    return {
        "score": score,
        "level": level,
        "max_score": 100,
        "breakdown": breakdown,
    }


if __name__ == "__main__":
    # Demo: score INC-1024 indicators
    demo_indicators = {
        "failed_attempts": 45,
        "successful_suspicious_login": True,
        "suspicious_process": True,
        "unusual_connection": True,
        "source_ip": "10.0.0.25",
    }

    if len(sys.argv) > 1:
        # Accept a JSON file path as argument
        indicators_path = Path(sys.argv[1])
        demo_indicators = json.loads(indicators_path.read_text())

    result = compute_risk_score(demo_indicators)
    print(json.dumps(result, indent=2))

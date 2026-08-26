import sys
import json
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

from search_security_logs import search_security_logs
from check_system_activity import check_system_activity


def analyze_evidence() -> dict:
    """Correlate authentication, process, and network evidence."""

    auth = search_security_logs("10.0.0.25")
    activity = check_system_activity()

    findings = []

    if auth.get("failed_logins", 0) >= 20:
        findings.append(
            "High volume of failed SSH authentication attempts."
        )

    if auth.get("successful_logins", 0) > 0:
        findings.append(
            "Successful SSH login occurred after repeated failures."
        )

    if activity.get("suspicious_process_count", 0) > 0:
        findings.append(
            "Suspicious process detected after successful login."
        )

    if activity.get("unusual_connection_count", 0) > 0:
        findings.append(
            "Unusual network connection to port 4444 detected."
        )

    risk_indicators = {
        "failed_attempts": auth.get("failed_logins", 0),
        "successful_suspicious_login": auth.get("successful_logins", 0) > 0,
        "suspicious_process": activity.get("suspicious_process_count", 0) > 0,
        "unusual_connection": activity.get("unusual_connection_count", 0) > 0,
        "source_ip": "10.0.0.25",
    }

    return {
        "success": True,
        "incident_id": "INC-1024",
        "source_ip": "10.0.0.25",
        "findings": findings,
        "risk_indicators": risk_indicators
    }


if __name__ == "__main__":
    print(json.dumps(analyze_evidence(), indent=2))
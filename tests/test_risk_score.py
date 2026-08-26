"""Tests for CyberForge Risk Scoring Engine."""

import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"
sys.path.insert(0, str(AGENT_DIR))

from risk_score import compute_risk_score


class TestRiskScoring:
    def test_all_indicators_critical(self):
        indicators = {
            "failed_attempts": 45,
            "successful_suspicious_login": True,
            "suspicious_process": True,
            "unusual_connection": True,
            "source_ip": "10.0.0.25",
        }
        result = compute_risk_score(indicators)
        assert result["score"] == 100
        assert result["level"] == "CRITICAL"

    def test_no_indicators_low(self):
        indicators = {
            "failed_attempts": 5,
            "successful_suspicious_login": False,
            "suspicious_process": False,
            "unusual_connection": False,
            "source_ip": "192.168.1.1",
        }
        result = compute_risk_score(indicators)
        assert result["score"] == 0
        assert result["level"] == "LOW"

    def test_failed_attempts_only_medium(self):
        indicators = {
            "failed_attempts": 25,
            "successful_suspicious_login": False,
            "suspicious_process": False,
            "unusual_connection": False,
            "source_ip": "192.168.1.1",
        }
        result = compute_risk_score(indicators)
        assert result["score"] == 20
        assert result["level"] == "LOW"

    def test_successful_login_plus_process_high(self):
        indicators = {
            "failed_attempts": 0,
            "successful_suspicious_login": True,
            "suspicious_process": True,
            "unusual_connection": False,
            "source_ip": "192.168.1.1",
        }
        result = compute_risk_score(indicators)
        assert result["score"] == 50
        assert result["level"] == "MEDIUM"

    def test_three_indicators_high(self):
        indicators = {
            "failed_attempts": 30,
            "successful_suspicious_login": True,
            "suspicious_process": True,
            "unusual_connection": False,
            "source_ip": "192.168.1.1",
        }
        result = compute_risk_score(indicators)
        assert result["score"] == 70
        assert result["level"] == "HIGH"

    def test_known_bad_ip_bonus(self):
        indicators = {
            "failed_attempts": 30,
            "successful_suspicious_login": False,
            "suspicious_process": False,
            "unusual_connection": False,
            "source_ip": "10.0.0.25",
        }
        result = compute_risk_score(indicators)
        assert result["score"] == 30  # 20 (failed) + 10 (known bad)
        assert result["level"] == "MEDIUM"

    def test_empty_indicators(self):
        result = compute_risk_score({})
        assert result["score"] == 0
        assert result["level"] == "LOW"

    def test_breakdown_has_all_keys(self):
        indicators = {
            "failed_attempts": 20,
            "successful_suspicious_login": True,
            "suspicious_process": True,
            "unusual_connection": True,
            "source_ip": "10.0.0.25",
        }
        result = compute_risk_score(indicators)
        expected_keys = [
            "failed_attempts",
            "successful_suspicious_login",
            "suspicious_process",
            "unusual_connection",
            "known_bad_source",
        ]
        for key in expected_keys:
            assert key in result["breakdown"], f"Missing breakdown key: {key}"


def run_all():
    passed = 0
    failed = 0
    errors = []

    instance = TestRiskScoring()
    methods = [m for m in dir(instance) if m.startswith("test_")]
    for method_name in methods:
        method = getattr(instance, method_name)
        try:
            method()
            print(f"  PASS  TestRiskScoring.{method_name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  TestRiskScoring.{method_name}: {e}")
            failed += 1
            errors.append(f"{method_name}: {e}")

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for e in errors:
            print(f"  - {e}")
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)

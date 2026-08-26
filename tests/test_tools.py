"""Tests for CyberForge MCP investigation tools."""

import sys
import json
from pathlib import Path

# Add tools directory to path
TOOLS_DIR = Path(__file__).resolve().parent.parent / "mcp_server" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

from search_security_logs import search_security_logs
from check_system_activity import check_system_activity
from analyze_evidence import analyze_evidence
from block_ip import block_ip


class TestSearchSecurityLogs:
    def test_search_by_ip(self):
        result = search_security_logs("10.0.0.25")
        assert result["success"] is True
        assert result["match_count"] > 0
        assert result["failed_logins"] >= 20
        assert result["successful_logins"] > 0

    def test_search_empty_query_returns_all(self):
        result = search_security_logs("")
        assert result["success"] is True
        assert result["match_count"] > 0

    def test_search_no_matches(self):
        result = search_security_logs("192.168.99.99")
        assert result["success"] is True
        assert result["match_count"] == 0
        assert result["failed_logins"] == 0


class TestCheckSystemActivity:
    def test_returns_processes(self):
        result = check_system_activity()
        assert result["success"] is True
        assert result["process_count"] >= 3
        assert result["suspicious_process_count"] >= 1
        assert result["unusual_connection_count"] >= 1

    def test_suspicious_process_detected(self):
        result = check_system_activity()
        assert len(result["suspicious_processes"]) > 0
        assert "suspicious" in result["suspicious_processes"][0]["command"].lower()

    def test_unusual_connections_detected(self):
        result = check_system_activity()
        assert len(result["unusual_connections"]) > 0
        assert "port=4444" in result["unusual_connections"][0]


class TestAnalyzeEvidence:
    def test_returns_complete_findings(self):
        result = analyze_evidence()
        assert result["success"] is True
        assert result["incident_id"] == "INC-1024"
        assert result["source_ip"] == "10.0.0.25"
        assert len(result["findings"]) >= 3

    def test_risk_indicators_present(self):
        result = analyze_evidence()
        indicators = result["risk_indicators"]
        assert indicators["failed_attempts"] >= 20
        assert indicators["successful_suspicious_login"] is True
        assert indicators["suspicious_process"] is True
        assert indicators["unusual_connection"] is True


class TestBlockIp:
    def test_block_ip_success(self, tmp_path, monkeypatch):
        # Use a temp file for firewall data
        firewall_file = tmp_path / "firewall.json"
        monkeypatch.setattr(
            "block_ip.FIREWALL_FILE", firewall_file
        )
        from block_ip import block_ip as bip

        result = bip("192.168.1.100")
        assert result["success"] is True
        assert result["mode"] == "SIMULATED"
        assert result["ip"] == "192.168.1.100"

    def test_block_ip_empty_address(self):
        result = block_ip("")
        assert result["success"] is False
        assert "required" in result["error"].lower()


def run_all():
    """Run tests manually without pytest."""
    passed = 0
    failed = 0
    errors = []

    test_classes = [
        TestSearchSecurityLogs,
        TestCheckSystemActivity,
        TestAnalyzeEvidence,
        TestBlockIp,
    ]

    for cls in test_classes:
        instance = cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        for method_name in methods:
            method = getattr(instance, method_name)
            try:
                # Skip tests requiring fixtures
                if "monkeypatch" in method.__code__.co_varnames:
                    print(f"  SKIP  {cls.__name__}.{method_name} (requires fixtures)")
                    continue
                method()
                print(f"  PASS  {cls.__name__}.{method_name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {cls.__name__}.{method_name}: {e}")
                failed += 1
                errors.append(f"{cls.__name__}.{method_name}: {e}")

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

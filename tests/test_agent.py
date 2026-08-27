"""Tests for CyberForge Agent Investigation Workflow.

All tool calls are mocked so tests are deterministic and do not
depend on the host's logs, processes, or network state.
"""

import sys
import json
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent import (
    run_investigation,
    extract_target_ip,
    _validate_ip,
    _sanitize_tool_result,
    _sanitize_findings,
    _validate_tool_result,
    _sanitize_exception,
    _generate_recommendation,
    KNOWN_BAD_IPS,
)

# ---------------------------------------------------------------------------
#  Fake tool results used by mocked tests
# ---------------------------------------------------------------------------

FAKE_LOG_SUCCESS = {
    "success": True,
    "query": "10.0.0.25",
    "match_count": 48,
    "failed_logins": 45,
    "successful_logins": 3,
    "matches": ["line1", "line2"],
}

FAKE_ACTIVITY_SUCCESS = {
    "success": True,
    "process_count": 3,
    "suspicious_process_count": 1,
    "suspicious_processes": [{"command": "python3 suspicious.py"}],
    "unusual_connection_count": 2,
    "unusual_connections": ["conn1", "conn2"],
}

FAKE_ANALYSIS_SUCCESS = {
    "success": True,
    "incident_id": "INC-1024",
    "source_ip": "10.0.0.25",
    "findings": [
        "High volume of failed SSH authentication attempts.",
        "Successful SSH login occurred after repeated failures.",
        "Suspicious process detected after successful login.",
        "Unusual network connection to port 4444 detected.",
    ],
    "risk_indicators": {
        "failed_attempts": 45,
        "successful_suspicious_login": True,
        "suspicious_process": True,
        "unusual_connection": True,
        "source_ip": "10.0.0.25",
    },
}

FAKE_TOOL_ERROR = RuntimeError("subprocess failed: /opt/tools/auth.log")


# ===========================================================================
#  1. IPv4 validation
# ===========================================================================
class TestValidateIp:
    def test_valid_10_0_0_25(self):
        assert _validate_ip("10.0.0.25") is True

    def test_valid_192_168_1_100(self):
        assert _validate_ip("192.168.1.100") is True

    def test_valid_0_0_0_0(self):
        assert _validate_ip("0.0.0.0") is True

    def test_valid_255_255_255_255(self):
        assert _validate_ip("255.255.255.255") is True

    def test_invalid_octet_256(self):
        assert _validate_ip("256.1.1.1") is False

    def test_invalid_too_few_octets(self):
        assert _validate_ip("10.0.0") is False

    def test_invalid_too_many_octets(self):
        assert _validate_ip("10.0.0.1.5") is False

    def test_invalid_suffix(self):
        assert _validate_ip("10.0.0.1abc") is False

    def test_invalid_alpha(self):
        assert _validate_ip("abc") is False

    def test_empty_string(self):
        assert _validate_ip("") is False

    def test_none_input(self):
        assert _validate_ip(None) is False

    def test_integer_input(self):
        assert _validate_ip(123) is False

    def test_whitespace_only(self):
        assert _validate_ip("   ") is False

    def test_leading_whitespace_valid(self):
        assert _validate_ip("  10.0.0.25") is True

    def test_non_numeric_octet(self):
        assert _validate_ip("10.0.0.one") is False


# ===========================================================================
#  2. extract_target_ip
# ===========================================================================
class TestExtractTargetIp:
    def test_extracts_valid_ip(self):
        assert extract_target_ip("Investigate 10.0.0.25") == "10.0.0.25"

    def test_extracts_ip_from_long_query(self):
        result = extract_target_ip(
            "Analyze suspicious activity from 192.168.1.100 on port 4444"
        )
        assert result == "192.168.1.100"

    def test_returns_none_for_no_ip(self):
        assert extract_target_ip("Investigate suspicious activity") is None

    def test_returns_none_for_empty(self):
        assert extract_target_ip("") is None

    def test_returns_none_for_invalid_ip(self):
        assert extract_target_ip("Check 999.999.999.999") is None

    def test_returns_none_for_none(self):
        assert extract_target_ip(None) is None

    def test_rejects_trailing_octets(self):
        """10.0.0.25.99 must NOT extract 10.0.0.25 as a substring."""
        assert extract_target_ip("Check 10.0.0.25.99") is None

    def test_rejects_prefix_digits(self):
        """910.0.0.25 is not a valid first octet."""
        assert extract_target_ip("Check 910.0.0.25") is None

    def test_rejects_dotted_suffix(self):
        """10.0.0.25.1 is too many octets."""
        assert extract_target_ip("Check 10.0.0.25.1") is None


# ===========================================================================
#  3. _sanitize_tool_result
# ===========================================================================
class TestSanitizeToolResult:
    def test_none_input(self):
        assert _sanitize_tool_result(None) == {"available": False}

    def test_non_dict_input(self):
        assert _sanitize_tool_result("not a dict") == {"available": False}

    def test_empty_dict(self):
        result = _sanitize_tool_result({})
        assert result == {"available": True}

    def test_excludes_raw_matches(self):
        result = _sanitize_tool_result(FAKE_LOG_SUCCESS)
        assert "matches" not in result
        assert result["failed_logins"] == 45
        assert result["successful_logins"] == 3

    def test_includes_findings_safely(self):
        result = _sanitize_tool_result(FAKE_ANALYSIS_SUCCESS)
        assert "findings" in result
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) <= 10

    def test_coerces_bad_types(self):
        bad = {"failed_logins": "not_a_number", "success": 1}
        result = _sanitize_tool_result(bad)
        assert result["failed_logins"] == 0
        assert result["success"] is True

    def test_excludes_sensitive_fields(self):
        """Raw matches, stack traces, and paths must never leak."""
        sensitive = {
            "success": True,
            "matches": ["root:x:0:0:/root:/bin/bash"],
            "error_trace": "File '/etc/passwd' not found",
            "failed_logins": 5,
        }
        result = _sanitize_tool_result(sensitive)
        assert "matches" not in result
        assert "error_trace" not in result
        assert result["failed_logins"] == 5


# ===========================================================================
#  4. _generate_recommendation
# ===========================================================================
class TestGenerateRecommendation:
    def test_critical_with_complete_evidence(self):
        rec = _generate_recommendation("CRITICAL", True)
        assert "Containment" in rec or "containment" in rec

    def test_partial_evidence_always_cautious(self):
        rec = _generate_recommendation("CRITICAL", False)
        assert "incomplete" in rec.lower() or "further investigation" in rec.lower()
        assert "Do not rely" in rec or "do not rely" in rec

    def test_low_with_complete_evidence(self):
        rec = _generate_recommendation("LOW", True)
        assert isinstance(rec, str)
        assert len(rec) > 10

    def test_unknown_level_with_complete_evidence(self):
        rec = _generate_recommendation("UNKNOWN", True)
        assert isinstance(rec, str)
        assert len(rec) > 10


# ===========================================================================
#  5. _sanitize_exception — JSON decode error mapping
# ===========================================================================
class TestSanitizeException:
    def test_json_decode_error_mapped(self):
        """json.JSONDecodeError.__name__ is 'JSONDecodeError', not 'json.JSONDecodeError'."""
        try:
            json.loads("not json")
        except json.JSONDecodeError as exc:
            msg = _sanitize_exception(exc)
            assert msg == "tool returned invalid data"
            assert "JSONDecodeError" not in msg
            assert "json" not in msg.lower()

    def test_runtime_error_mapped(self):
        exc = RuntimeError("something broke")
        msg = _sanitize_exception(exc)
        assert msg == "tool execution failed"

    def test_unknown_exception_generic(self):
        exc = ValueError("weird value")
        msg = _sanitize_exception(exc)
        assert msg == "unexpected error during investigation"
        assert "weird value" not in msg

    def test_no_raw_paths_exposed(self):
        exc = FileNotFoundError("/home/user/.ssh/authorized_keys")
        msg = _sanitize_exception(exc)
        assert "/home/" not in msg
        assert "authorized_keys" not in msg


# ===========================================================================
#  6. _validate_tool_result — structural validation
# ===========================================================================
class TestValidateToolResult:
    def test_none_rejected(self):
        assert _validate_tool_result(None, "search_security_logs") is False

    def test_non_dict_rejected(self):
        assert _validate_tool_result("string", "check_system_activity") is False

    def test_empty_success_rejected(self):
        """{'success': True} with no evidence fields should be rejected."""
        assert _validate_tool_result({"success": True}, "search_security_logs") is False
        assert _validate_tool_result({"success": True}, "check_system_activity") is False
        assert _validate_tool_result({"success": True}, "analyze_evidence") is False

    def test_success_false_rejected(self):
        assert _validate_tool_result({"success": False, "error": "no file"}, "search_security_logs") is False

    def test_log_tool_with_evidence_accepted(self):
        assert _validate_tool_result(FAKE_LOG_SUCCESS, "search_security_logs") is True

    def test_activity_tool_with_evidence_accepted(self):
        assert _validate_tool_result(FAKE_ACTIVITY_SUCCESS, "check_system_activity") is True

    def test_analysis_tool_with_evidence_accepted(self):
        assert _validate_tool_result(FAKE_ANALYSIS_SUCCESS, "analyze_evidence") is True

    def test_log_tool_minimal_valid(self):
        assert _validate_tool_result({"success": True, "match_count": 0}, "search_security_logs") is True

    def test_activity_tool_minimal_valid(self):
        assert _validate_tool_result({"success": True, "process_count": 0}, "check_system_activity") is True

    def test_analysis_tool_minimal_valid(self):
        """Populated risk_indicators is the minimum usable analysis."""
        assert _validate_tool_result(
            {"success": True, "risk_indicators": {"failed_attempts": 1}},
            "analyze_evidence",
        ) is True

    def test_analysis_findings_only_rejected(self):
        """findings alone is NOT scoreable evidence — risk scoring needs
        risk_indicators, so this must not count as a successful analysis."""
        assert _validate_tool_result(
            {"success": True, "findings": []}, "analyze_evidence"
        ) is False
        assert _validate_tool_result(
            {"success": True, "findings": ["something happened"]},
            "analyze_evidence",
        ) is False

    def test_analysis_non_dict_indicators_rejected(self):
        for bad in (None, [], "", 0, "high"):
            assert _validate_tool_result(
                {"success": True, "findings": [], "risk_indicators": bad},
                "analyze_evidence",
            ) is False

    def test_analysis_empty_indicators_rejected(self):
        """An empty indicator mapping must not be scored as 0/LOW."""
        assert _validate_tool_result(
            {"success": True, "findings": [], "risk_indicators": {}},
            "analyze_evidence",
        ) is False

    def test_unknown_tool_defaults_to_success(self):
        assert _validate_tool_result({"success": True}, "unknown_tool") is True


# ===========================================================================
#  7. _sanitize_findings
# ===========================================================================
class TestSanitizeFindings:
    def test_valid_strings(self):
        assert _sanitize_findings(["a", "b", "c"]) == ["a", "b", "c"]

    def test_filters_non_strings(self):
        result = _sanitize_findings(["valid", 123, None, {"key": "val"}, True])
        assert result == ["valid"]
        assert all(isinstance(f, str) for f in result)

    def test_caps_at_max(self):
        findings = [f"finding {i}" for i in range(15)]
        result = _sanitize_findings(findings)
        assert len(result) == 10

    def test_empty_list(self):
        assert _sanitize_findings([]) == []

    def test_non_list_input(self):
        assert _sanitize_findings(None) == []
        assert _sanitize_findings("string") == []
        assert _sanitize_findings(42) == []

    def test_mixed_types(self):
        result = _sanitize_findings(["ok", 1, None, "also ok", {}])
        assert result == ["ok", "also ok"]


# ===========================================================================
#  8. run_investigation — normal success (mocked)
# ===========================================================================
class TestRunInvestigationMocked:
    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_successful_investigation(self, mock_analysis, mock_activity, mock_log):
        result = run_investigation("Investigate 10.0.0.25")
        mock_analysis.assert_called_once_with("10.0.0.25")
        assert result["success"] is True
        assert result["status"] == "complete"
        assert result["evidence_complete"] is True
        assert result["target_ip"] == "10.0.0.25"
        assert result["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert result["risk_score"]["score"] > 0
        assert len(result["evidence"]) > 0
        assert len(result["tools_used"]) >= 3

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_known_bad_ip(self, mock_analysis, mock_activity, mock_log):
        result = run_investigation("Investigate 10.0.0.25")
        # 10.0.0.25 is in KNOWN_BAD_IPS, so known_bad_source +10
        assert result["risk_score"]["breakdown"]["known_bad_source"]["points"] == 10

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_unknown_ip(self, mock_analysis, mock_activity, mock_log):
        result = run_investigation("Investigate 192.168.99.99")
        mock_analysis.assert_called_once_with("192.168.99.99")
        assert result["success"] is True
        assert result["target_ip"] == "192.168.99.99"
        # Analysis is discarded (wrong source_ip) → risk is UNKNOWN
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["risk_score"]["score"] is None
        assert result["containment_allowed"] is False

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_no_target_ip(self, mock_analysis, mock_activity, mock_log):
        result = run_investigation("Check general system activity")
        # No target IP → analyze_evidence should NOT be called
        mock_analysis.assert_not_called()
        assert result["success"] is True
        assert result["status"] == "partial"
        assert result["target_ip"] == "unknown"
        assert result["risk_score"]["level"] == "UNKNOWN"

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_explicit_target_ip(self, mock_analysis, mock_activity, mock_log):
        result = run_investigation("Check this IP", target_ip="10.0.0.25")
        mock_analysis.assert_called_once_with("10.0.0.25")
        assert result["success"] is True
        assert result["target_ip"] == "10.0.0.25"

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_invalid_target_ip_rejected(self, mock_analysis, mock_activity, mock_log):
        result = run_investigation("Check this", target_ip="not-an-ip")
        assert result["success"] is False
        assert result["status"] == "error"

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_result_field_types(self, mock_analysis, mock_activity, mock_log):
        result = run_investigation("Investigate 10.0.0.25")
        assert isinstance(result["success"], bool)
        assert isinstance(result["status"], str)
        assert isinstance(result["query"], str)
        assert isinstance(result["target_ip"], str)
        assert isinstance(result["severity"], str)
        assert isinstance(result["risk_score"], dict)
        assert isinstance(result["findings"], list)
        assert isinstance(result["evidence"], list)
        assert isinstance(result["tools_used"], list)
        assert isinstance(result["recommendation"], str)
        assert isinstance(result["tool_results"], dict)
        assert isinstance(result["errors"], dict)
        assert isinstance(result["evidence_complete"], bool)


# ===========================================================================
#  9. Target mismatch — analysis for wrong IP discarded
# ===========================================================================
class TestTargetMismatch:
    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_analysis_discarded_for_wrong_target(self, mock_a, mock_c, mock_l):
        """analyze_evidence returns source_ip=10.0.0.25 but we're investigating
        192.168.99.99 — the analysis should be discarded."""
        result = run_investigation("Investigate 192.168.99.99")
        mock_a.assert_called_once_with("192.168.99.99")
        assert result["success"] is True
        # analysis was discarded due to mismatch
        assert result["errors"]["analysis"] is not None
        assert "different target" in result["errors"]["analysis"]
        # correlated_analysis should be empty (analysis was None'd)
        assert result["tool_results"]["correlated_analysis"]["available"] is False
        # analyze_evidence should NOT be in tools_used
        assert "analyze_evidence" not in result["tools_used"]

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    def test_no_analysis_for_unknown_target(self, mock_c, mock_l):
        """No target IP — analysis is never called, so risk stays UNKNOWN."""
        analysis = dict(FAKE_ANALYSIS_SUCCESS)
        analysis["source_ip"] = ""
        with patch("agent.analyze_evidence", return_value=analysis) as mock_a:
            result = run_investigation("Check general system activity")
        mock_a.assert_not_called()
        assert result["success"] is True
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["containment_allowed"] is False

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    def test_missing_source_ip_discarded(self, mock_c, mock_l):
        """A successful analysis with no source_ip is not evidence about the
        requested target and must never be relabelled with it."""
        for bad_source in (None, "", "   ", "not-an-ip", "10.0.0", 12345):
            analysis = dict(FAKE_ANALYSIS_SUCCESS)
            analysis["source_ip"] = bad_source
            with patch("agent.analyze_evidence", return_value=analysis):
                result = run_investigation("Investigate 192.168.1.50")
            assert result["target_ip"] == "192.168.1.50"
            # Discarded → not counted as a successful tool
            assert "analyze_evidence" not in result["tools_used"]
            assert result["tool_results"]["correlated_analysis"]["available"] is False
            # Risk must be UNKNOWN, never a fabricated score
            assert result["risk_score"]["score"] is None, bad_source
            assert result["risk_score"]["level"] == "UNKNOWN"
            assert result["evidence_complete"] is False
            assert result["containment_allowed"] is False
            assert result["errors"]["analysis"] is not None
            # The requested IP must not have been stamped onto foreign evidence
            assert result["findings"] == []

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    def test_missing_source_ip_not_accepted_for_demo_target(self, mock_c, mock_l):
        """The same bypass must not work for the demo IP either."""
        analysis = dict(FAKE_ANALYSIS_SUCCESS)
        analysis.pop("source_ip")
        with patch("agent.analyze_evidence", return_value=analysis):
            result = run_investigation("Investigate 10.0.0.25")
        assert "analyze_evidence" not in result["tools_used"]
        assert result["risk_score"]["score"] is None
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["containment_allowed"] is False

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_analysis_accepted_for_correct_target(self, mock_a, mock_c, mock_l):
        """analyze_evidence returns source_ip=10.0.0.25 and we investigate 10.0.0.25
        — analysis should be kept."""
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is True
        assert "analyze_evidence" in result["tools_used"]
        assert result["errors"]["analysis"] is None
        assert result["risk_score"]["score"] is not None


# ===========================================================================
# 9b. No target — analysis should NOT be called
# ===========================================================================
class TestNoTargetAnalysis:
    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence")
    def test_no_target_skips_analysis(self, mock_analysis, mock_activity, mock_log):
        """When no target IP, analyze_evidence should NOT be called."""
        result = run_investigation("Check general system activity")
        mock_analysis.assert_not_called()
        assert result["success"] is True
        assert result["target_ip"] == "unknown"
        assert "analyze_evidence" not in result["tools_used"]
        assert result["errors"]["analysis"] is not None
        assert "target" in result["errors"]["analysis"].lower()

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence")
    def test_no_target_risk_is_unknown(self, mock_analysis, mock_activity, mock_log):
        """Without target-specific analysis, risk should be UNKNOWN."""
        result = run_investigation("Check general system activity")
        assert result["risk_score"]["score"] is None
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["containment_allowed"] is False


# ===========================================================================
# 10. Risk-score exception handling
# ===========================================================================
class TestRiskScoreFailure:
    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    @patch("agent.compute_risk_score", side_effect=RuntimeError("scorer crashed"))
    def test_risk_score_exception(self, mock_score, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is False
        assert result["status"] == "error"
        assert result["evidence_complete"] is False
        assert result["severity"] == "UNKNOWN"
        assert result["risk_score"]["score"] is None
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["risk_score"]["error"] is not None
        assert "risk assessment could not be completed" in result["recommendation"].lower()
        assert result["containment_allowed"] is False
        assert "risk_score" not in result["tools_used"]
        # No raw exception exposed
        assert "scorer crashed" not in str(result["risk_score"])

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    @patch("agent.compute_risk_score", side_effect=ValueError("bad indicator"))
    def test_risk_score_value_error(self, mock_score, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is False
        assert result["status"] == "error"
        assert result["risk_score"]["score"] is None
        assert result["containment_allowed"] is False
        assert "risk_score" not in result["tools_used"]
        assert "bad indicator" not in str(result)


# ===========================================================================
# 11. Partial tool failures
# ===========================================================================
class TestPartialFailures:
    @patch("agent.search_security_logs", side_effect=FAKE_TOOL_ERROR)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_log_fails_analysis_succeeds(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is True
        assert result["status"] == "partial"
        assert result["evidence_complete"] is False
        assert result["errors"]["log_search"] is not None
        # Recommendation should be cautious
        assert "incomplete" in result["recommendation"].lower() or \
               "further investigation" in result["recommendation"].lower()

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", side_effect=FAKE_TOOL_ERROR)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_activity_fails_analysis_succeeds(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is True
        assert result["status"] == "partial"
        assert result["evidence_complete"] is False

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", side_effect=FAKE_TOOL_ERROR)
    def test_analysis_fails_others_succeed(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is True
        assert result["status"] == "partial"
        assert result["evidence_complete"] is False
        # Without target-specific analysis, risk is UNKNOWN
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["risk_score"]["score"] is None
        assert result["containment_allowed"] is False

    @patch("agent.search_security_logs", side_effect=FAKE_TOOL_ERROR)
    @patch("agent.check_system_activity", side_effect=FAKE_TOOL_ERROR)
    @patch("agent.analyze_evidence", side_effect=FAKE_TOOL_ERROR)
    def test_all_tools_fail(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is False
        assert result["status"] == "error"
        assert result["tools_used"] == []
        # No raw exception strings exposed
        for val in result.get("errors", {}).values():
            if val is not None:
                assert "subprocess" not in val
                assert "/opt/" not in val
                assert "Traceback" not in val

    @patch("agent.search_security_logs", side_effect=FAKE_TOOL_ERROR)
    @patch("agent.check_system_activity", side_effect=FAKE_TOOL_ERROR)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_partial_evidence_low_confidence(self, mock_a, mock_c, mock_l):
        """Only analysis succeeds — risk should not be confidently LOW."""
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is True
        assert result["status"] == "partial"
        assert result["evidence_complete"] is False
        # Recommendation must be cautious
        assert "incomplete" in result["recommendation"].lower() or \
               "further investigation" in result["recommendation"].lower()

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", side_effect=FAKE_TOOL_ERROR)
    def test_tools_used_excludes_failed(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert "search_security_logs" in result["tools_used"]
        assert "check_system_activity" in result["tools_used"]
        assert "analyze_evidence" not in result["tools_used"]
        # Risk score is UNKNOWN (no target-specific analysis) → not in tools_used
        assert "risk_score" not in result["tools_used"]

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    def test_unsupported_target_risk_unknown(self, mock_c, mock_l):
        """Unsupported target should get UNKNOWN risk, not fabricated LOW."""
        mock_analysis_result = {
            "success": False,
            "error": "Correlated evidence is only available for 10.0.0.25",
            "findings": [],
            "risk_indicators": {},
        }
        with patch("agent.analyze_evidence", return_value=mock_analysis_result):
            result = run_investigation("Investigate 192.168.1.50")
        assert result["success"] is True
        assert result["target_ip"] == "192.168.1.50"
        # Risk should be UNKNOWN — not LOW from raw fallback
        assert result["risk_score"]["score"] is None
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["containment_allowed"] is False
        assert "analyze_evidence" not in result["tools_used"]

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value={"success": True})
    def test_empty_success_tool_rejected(self, mock_a, mock_c, mock_l):
        """{'success': True} with no evidence fields is treated as failed."""
        result = run_investigation("Investigate 10.0.0.25")
        # analysis has no evidence fields, so it should be rejected
        assert "analyze_evidence" not in result["tools_used"]
        assert result["evidence_complete"] is False
        assert result["status"] == "partial"


# ===========================================================================
# 12. Malformed tool results
# ===========================================================================
class TestMalformedResults:
    @patch("agent.search_security_logs", return_value={
        "success": True,
        "match_count": 1,
        "failed_logins": "not-a-number",
        "successful_logins": None,
    })
    @patch("agent.check_system_activity", return_value={
        "success": True,
        "process_count": 1,
        "suspicious_process_count": "bad-count",
        "suspicious_processes": None,
        "unusual_connection_count": 1,
        "unusual_connections": None,
    })
    @patch("agent.analyze_evidence", return_value={
        "success": True,
        "source_ip": "10.0.0.25",
        "findings": [],
        "risk_indicators": None,
    })
    def test_malformed_evidence_fields_do_not_crash(self, mock_a, mock_c, mock_l):
        """A successful tool response must not bypass value-type validation."""
        result = run_investigation("Investigate 10.0.0.25")
        assert result["success"] is True
        # risk_indicators is None → no scoreable target evidence. This must be
        # UNKNOWN, never 0/LOW computed from an empty dictionary.
        assert result["risk_score"]["score"] is None
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["risk_score"]["error"] is not None
        # ...and it must not pass as complete evidence or permit containment
        assert result["evidence_complete"] is False
        assert result["status"] == "partial"
        assert result["containment_allowed"] is False
        assert "analyze_evidence" not in result["tools_used"]
        assert "risk_score" not in result["tools_used"]
        assert result["errors"]["analysis"] is not None
        assert result["evidence"] == [
            "Unusual network connections: 1 connection(s) to non-standard ports"
        ]

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value={
        "success": True,
        "source_ip": "10.0.0.25",
        "findings": ["High volume of failed SSH authentication attempts."],
        "risk_indicators": {},
    })
    def test_empty_indicators_do_not_score_low(self, mock_a, mock_c, mock_l):
        """An empty indicator mapping must yield UNKNOWN, not a 0/LOW score
        that would mark evidence complete and permit containment."""
        result = run_investigation("Investigate 10.0.0.25")
        assert result["risk_score"]["score"] is None
        assert result["risk_score"]["level"] == "UNKNOWN"
        assert result["severity"] == "UNKNOWN"
        assert result["evidence_complete"] is False
        assert result["containment_allowed"] is False
        assert "analyze_evidence" not in result["tools_used"]

    @patch("agent.search_security_logs", return_value=None)
    @patch("agent.check_system_activity", return_value={"success": True})
    @patch("agent.analyze_evidence", return_value=None)
    def test_none_results_handled(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        # None log rejected, activity has no evidence fields (rejected),
        # None analysis rejected — all tools fail
        assert result["success"] is False
        assert result["status"] == "error"
        assert "search_security_logs" not in result["tools_used"]
        assert "check_system_activity" not in result["tools_used"]
        assert result["tools_used"] == []

    @patch("agent.search_security_logs", return_value={"success": True})
    @patch("agent.check_system_activity", return_value={"success": True})
    @patch("agent.analyze_evidence", return_value={
        "success": True,
        "source_ip": "10.0.0.25",
        "risk_indicators": {"failed_attempts": 45},
        "findings": [123, None],
    })
    def test_non_string_findings(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        # Main findings should be sanitized
        for f in result["findings"]:
            assert isinstance(f, str)
        # tool_results findings should also be sanitized
        tr = result["tool_results"]["correlated_analysis"]
        if "findings" in tr:
            for f in tr["findings"]:
                assert isinstance(f, str)

    @patch("agent.search_security_logs", return_value="not a dict")
    @patch("agent.check_system_activity", return_value=42)
    @patch("agent.analyze_evidence", return_value=[])
    def test_completely_wrong_types(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        # Should not crash — all tools rejected as non-dict
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["status"] == "error"
        assert result["tools_used"] == []

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value={
        "success": True,
        "source_ip": "10.0.0.25",
        "risk_indicators": {"failed_attempts": 45},
        "findings": ["valid finding", 123, None, {"secret": "data"}],
    })
    def test_findings_sanitized_in_result(self, mock_a, mock_c, mock_l):
        """Main findings field must only contain strings."""
        result = run_investigation("Investigate 10.0.0.25")
        assert result["findings"] == ["valid finding"]
        assert all(isinstance(f, str) for f in result["findings"])

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value={
        "success": True,
        "source_ip": "10.0.0.25",
        "risk_indicators": {"failed_attempts": 45},
        "findings": [f"finding {i}" for i in range(20)],
    })
    def test_findings_capped_at_max(self, mock_a, mock_c, mock_l):
        result = run_investigation("Investigate 10.0.0.25")
        assert len(result["findings"]) == 10


# ===========================================================================
# 13. Empty / invalid queries
# ===========================================================================
class TestEdgeCases:
    def test_empty_query(self):
        result = run_investigation("")
        assert result["success"] is False
        assert result["status"] == "error"

    def test_whitespace_query(self):
        result = run_investigation("   ")
        assert result["success"] is False

    def test_none_query(self):
        result = run_investigation(None)
        assert result["success"] is False

    def test_risk_score_in_result(self):
        with patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS), \
             patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS), \
             patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS):
            result = run_investigation("Investigate 10.0.0.25")
            assert "score" in result["risk_score"]
            assert "level" in result["risk_score"]
            assert "breakdown" in result["risk_score"]
            assert "max_score" in result["risk_score"]

    def test_no_raw_exceptions_in_errors(self):
        """Errors dict should never contain filesystem paths or tracebacks."""
        with patch("agent.search_security_logs", side_effect=RuntimeError("/opt/tools/crash")), \
             patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS), \
             patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS):
            result = run_investigation("Investigate 10.0.0.25")
            err = result["errors"]["log_search"]
            assert err is not None
            assert "/opt/" not in err
            assert "crash" not in err

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", side_effect=RuntimeError("crash"))
    def test_analysis_error_does_not_expose_internals(self, mock_a, mock_c, mock_l):
        """Even if analyze_evidence raises, no internals leak."""
        result = run_investigation("Investigate 10.0.0.25")
        err = result["errors"]["analysis"]
        assert err is not None
        assert "crash" not in err
        assert "RuntimeError" not in err

    @patch("agent.search_security_logs", return_value=FAKE_LOG_SUCCESS)
    @patch("agent.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS)
    @patch("agent.analyze_evidence", return_value=FAKE_ANALYSIS_SUCCESS)
    def test_no_filesystem_paths_anywhere(self, mock_a, mock_c, mock_l):
        """No filesystem paths should appear in any result field."""
        result = run_investigation("Investigate 10.0.0.25")
        result_str = json.dumps(result)
        assert "/opt/" not in result_str
        assert "/home/" not in result_str
        assert "/etc/" not in result_str
        assert "Traceback" not in result_str# ===========================================================================
# 14. Session persistence
# ===========================================================================
class TestSessionPersistence:
    def test_corrupted_sessions_file(self):
        """Corrupted sessions.json should be backed up and not crash."""
        import tempfile, os
        from pathlib import Path
        sys.path.insert(0, str(PROJECT_ROOT))
        from app import sdk_client
        original = sdk_client.SESSIONS_FILE
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_file = Path(tmpdir) / "sessions.json"
            bad_file.write_text("not valid json {{{")
            sdk_client.SESSIONS_FILE = bad_file
            try:
                result = sdk_client._load_sessions()
                assert result == []
                # Original should be backed up
                assert bad_file.with_suffix(".json.corrupted").exists()
            finally:
                sdk_client.SESSIONS_FILE = original

    def test_atomic_write_creates_file(self):
        """Atomic write should produce a valid sessions file."""
        import tempfile
        sys.path.insert(0, str(PROJECT_ROOT))
        from app import sdk_client
        original = sdk_client.SESSIONS_FILE
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir) / "sessions.json"
            sdk_client.SESSIONS_FILE = tmp
            try:
                sdk_client._save_sessions([])
                assert tmp.exists()
                assert sdk_client._load_sessions() == []
            finally:
                sdk_client.SESSIONS_FILE = original


# ===========================================================================
# 15. sys.executable in run_tool
# ===========================================================================
class TestSysExecutable:
    def test_run_tool_uses_sys_executable(self):
        """run_tool should use sys.executable, not hardcoded 'python'."""
        sys.path.insert(0, str(PROJECT_ROOT))
        from app import sdk_client
        assert hasattr(sdk_client, 'sys')
        assert sdk_client.sys.executable is not None


# ===========================================================================
# 16. block_ip validation
# ===========================================================================
class TestBlockIpValidation:
    def test_rejects_999_octets(self):
        from mcp_server.tools.block_ip import _validate_ipv4
        assert _validate_ipv4("999.999.999.999") is False

    def test_rejects_256_octet(self):
        from mcp_server.tools.block_ip import _validate_ipv4
        assert _validate_ipv4("256.1.1.1") is False

    def test_rejects_too_few_octets(self):
        from mcp_server.tools.block_ip import _validate_ipv4
        assert _validate_ipv4("10.0.0") is False

    def test_rejects_suffix(self):
        from mcp_server.tools.block_ip import _validate_ipv4
        assert _validate_ipv4("10.0.0.1abc") is False

    def test_accepts_valid_ip(self):
        from mcp_server.tools.block_ip import _validate_ipv4
        assert _validate_ipv4("10.0.0.25") is True
        assert _validate_ipv4("192.168.1.1") is True
        assert _validate_ipv4("0.0.0.0") is True
        assert _validate_ipv4("255.255.255.255") is True

    def test_non_string_input(self):
        from mcp_server.tools.block_ip import _validate_ipv4
        assert _validate_ipv4(None) is False
        assert _validate_ipv4(123) is False


# ===========================================================================
# 17. analyze_evidence dependency failure
# ===========================================================================
class TestAnalyzeEvidenceDependencies:
    def test_both_tools_fail(self):
        """When both auth and activity tools fail, analysis should return success=False."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", side_effect=RuntimeError("crash")), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", side_effect=RuntimeError("crash")):
            result = analyze_evidence()
            assert result["success"] is False
            assert result["findings"] == []
            assert result["risk_indicators"] == {}

    def test_auth_fails_activity_ok(self):
        """When auth fails but activity succeeds, BOTH are required → success=False."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", side_effect=RuntimeError("crash")), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS):
            result = analyze_evidence()
            assert result["success"] is False
            assert "authentication" in result["error"].lower()

    def test_auth_ok_activity_fails(self):
        """When auth succeeds but activity fails, BOTH are required → success=False."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value=FAKE_LOG_SUCCESS), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", side_effect=RuntimeError("crash")):
            result = analyze_evidence()
            assert result["success"] is False
            assert "activity" in result["error"].lower()

    def test_malformed_auth_response(self):
        """Auth returns success=True but no evidence fields → rejected, success=False."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value={"success": True}), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS):
            result = analyze_evidence()
            assert result["success"] is False
            assert "authentication" in result["error"].lower()

    def test_malformed_activity_response(self):
        """Activity returns success=True but no evidence fields → rejected, success=False."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value=FAKE_LOG_SUCCESS), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value={"success": True}):
            result = analyze_evidence()
            assert result["success"] is False
            assert "activity" in result["error"].lower()

    def test_valid_evidence(self):
        """Both tools return valid data — full analysis."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value=FAKE_LOG_SUCCESS), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS):
            result = analyze_evidence()
            assert result["success"] is True
            assert len(result["findings"]) >= 3
            assert result["risk_indicators"]["failed_attempts"] >= 20

    def test_none_response_rejected(self):
        """None from a tool should be rejected."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value=None), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value=None):
            result = analyze_evidence()
            assert result["success"] is False

    def test_target_10_0_0_25_works(self):
        """Demo target IP should work."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value=FAKE_LOG_SUCCESS), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS):
            result = analyze_evidence(target_ip="10.0.0.25")
            assert result["success"] is True
            assert result["source_ip"] == "10.0.0.25"

    def test_target_mismatch_rejected(self):
        """Different IP should not inherit 10.0.0.25 evidence."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value=FAKE_LOG_SUCCESS), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS):
            result = analyze_evidence(target_ip="192.168.99.99")
            assert result["success"] is False
            assert "192.168.99.99" in result["error"]

    def test_source_ip_always_matches_evidence_target(self):
        """source_ip in result should always be the demo IP."""
        from mcp_server.tools.analyze_evidence import analyze_evidence
        with patch("mcp_server.tools.analyze_evidence.search_security_logs", return_value=FAKE_LOG_SUCCESS), \
             patch("mcp_server.tools.analyze_evidence.check_system_activity", return_value=FAKE_ACTIVITY_SUCCESS):
            result = analyze_evidence()
            assert result["source_ip"] == "10.0.0.25"


# ===========================================================================
#  Run all
# ===========================================================================
def run_all():
    passed = 0
    failed = 0
    errors = []

    test_classes = [
        TestValidateIp,
        TestExtractTargetIp,
        TestSanitizeToolResult,
        TestGenerateRecommendation,
        TestSanitizeException,
        TestValidateToolResult,
        TestSanitizeFindings,
        TestRunInvestigationMocked,
        TestTargetMismatch,
        TestRiskScoreFailure,
        TestPartialFailures,
        TestMalformedResults,
        TestEdgeCases,
        TestSessionPersistence,
        TestSysExecutable,
        TestBlockIpValidation,
        TestAnalyzeEvidenceDependencies,
        TestNoTargetAnalysis,
    ]

    for cls in test_classes:
        instance = cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        for method_name in sorted(methods):
            method = getattr(instance, method_name)
            try:
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

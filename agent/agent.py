"""
CyberForge Agent — Investigation Analysis Layer

Receives a user investigation query, selects and executes the appropriate
security tools, computes a risk score, and returns a structured finding.

This is the "brain" that sits between user input and tool execution.
"""

import re
import sys
from pathlib import Path

# Ensure package imports work both via ``python -m agent.agent`` and when this
# file is executed directly from the repository.
AGENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = AGENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp_server.tools.search_security_logs import search_security_logs
from mcp_server.tools.check_system_activity import check_system_activity
from mcp_server.tools.analyze_evidence import analyze_evidence
if __package__:
    from .risk_score import compute_risk_score
else:
    # Supports direct execution and the existing standalone test runner.
    from risk_score import compute_risk_score



# Default known-bad IPs for the demo
KNOWN_BAD_IPS = ["10.0.0.25"]

# IPv4 pattern: four dot-separated groups of 1-3 digits, surrounded
# by word boundaries so that "10.0.0.25.99" does NOT match "10.0.0.25".
# _validate_ip() uses fullmatch() for strict matching.
_IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
    r"(?!\d|\.)"
)

# Maximum findings returned in the result
_MAX_FINDINGS = 10


def _validate_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 address.

    Returns True only for complete, well-formed IPv4 addresses with
    octets in the range 0-255.  Never raises for malformed input.
    """
    if not isinstance(ip, str):
        return False
    match = _IPV4_PATTERN.fullmatch(ip.strip())
    if not match:
        return False
    for octet_str in match.groups():
        try:
            if int(octet_str) > 255:
                return False
        except (ValueError, TypeError):
            return False
    return True


def extract_target_ip(query: str) -> str | None:
    """Extract a valid IP address from the user query, or return None."""
    if not isinstance(query, str):
        return None
    for match in _IPV4_PATTERN.finditer(query):
        candidate = match.group(0)
        if _validate_ip(candidate):
            return candidate
    return None


def _sanitize_exception(exc: Exception) -> str:
    """Return a safe, generic error string. Never leaks internals."""
    name = type(exc).__name__
    # Map known exception types to safe messages
    # Note: json.JSONDecodeError.__name__ is "JSONDecodeError" (no prefix)
    safe_messages = {
        "TimeoutError": "tool execution timed out",
        "FileNotFoundError": "evidence data not available",
        "PermissionError": "evidence data not accessible",
        "JSONDecodeError": "tool returned invalid data",
        "RuntimeError": "tool execution failed",
        "OSError": "system error during tool execution",
    }
    return safe_messages.get(name, "unexpected error during investigation")


def _validate_tool_result(result: dict, tool_name: str) -> bool:
    """Lightweight structural validation for tool results.

    Returns True if the result contains meaningful evidence fields,
    False if it looks successful but has no useful data.

    This prevents {"success": True} (no evidence) from being treated
    as a fully successful tool invocation.
    """
    if not isinstance(result, dict):
        return False
    if not result.get("success"):
        return False

    if tool_name == "search_security_logs":
        # Must have match_count or failed_logins to indicate real evidence
        return ("match_count" in result or "failed_logins" in result
                or "successful_logins" in result)

    if tool_name == "check_system_activity":
        # Must have process_count or activity indicators
        return ("process_count" in result
                or "suspicious_process_count" in result
                or "unusual_connection_count" in result)

    if tool_name == "analyze_evidence":
        # Must have findings or risk_indicators
        return ("findings" in result or "risk_indicators" in result)

    # Unknown tool: accept if success=True
    return True


def _sanitize_findings(findings) -> list[str]:
    """Return a safe list of string findings.

    Filters out non-string values and caps at _MAX_FINDINGS items.
    Never exposes arbitrary objects.
    """
    if not isinstance(findings, list):
        return []
    return [str(f) for f in findings if isinstance(f, str)][:_MAX_FINDINGS]


def _safe_count(value) -> int:
    """Convert an untrusted evidence count to a non-negative integer."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _safe_list(value) -> list:
    """Return a list only when a tool supplied an actual list."""
    return value if isinstance(value, list) else []


def run_investigation(query: str, target_ip: str | None = None) -> dict:
    """
    Run a complete security investigation.

    Args:
        query: User's investigation query text.
        target_ip: Optional explicit target IP. If not provided,
                   extracted from the query.

    Returns:
        Structured investigation result with severity, findings,
        evidence, tool results, and recommendation.
    """
    # Validate query
    if not isinstance(query, str) or not query.strip():
        return {
            "success": False,
            "status": "error",
            "error": "Investigation query cannot be empty.",
            "target_ip": target_ip,
            "query": query,
        }

    # Validate explicit target_ip
    if target_ip is not None:
        if not isinstance(target_ip, str) or not _validate_ip(target_ip):
            return {
                "success": False,
                "status": "error",
                "error": "Invalid target_ip format. Expected a valid IPv4 address.",
                "target_ip": target_ip,
                "query": query,
            }
        target_ip = target_ip.strip()

    # Extract target IP from query if not provided
    if not target_ip:
        target_ip = extract_target_ip(query)

    # Step 1: Run security log search
    log_result = None
    log_error = None
    try:
        log_result = search_security_logs(target_ip or "")
    except Exception as exc:
        log_error = _sanitize_exception(exc)

    # Step 2: Check system activity
    activity_result = None
    activity_error = None
    try:
        activity_result = check_system_activity()
    except Exception as exc:
        activity_error = _sanitize_exception(exc)

    # Step 3: Correlate evidence.
    # When no target IP is known, do NOT call analyze_evidence — the
    # analyzer only has evidence for the demo IP (10.0.0.25) and calling
    # it without a target would silently analyze 10.0.0.25 for a
    # targetless query.
    analysis_result = None
    analysis_error = None
    analysis_mismatch = False
    if target_ip:
        try:
            analysis_result = analyze_evidence(target_ip)
        except Exception as exc:
            analysis_error = _sanitize_exception(exc)

        # Defense-in-depth: reject any analysis whose source does not
        # match the requested target.
        if analysis_result and isinstance(analysis_result, dict):
            analysis_source_ip = analysis_result.get("source_ip", "")
            if analysis_source_ip and analysis_source_ip != target_ip:
                analysis_mismatch = True
                analysis_error = (
                    "Analysis results are for a different target "
                    f"({analysis_source_ip}) and were discarded"
                )
                analysis_result = None
    else:
        analysis_error = (
            "No target IP provided — correlated analysis requires a target"
        )

    # Determine which tools succeeded — require valid structural evidence
    log_ok = _validate_tool_result(log_result, "search_security_logs")
    activity_ok = _validate_tool_result(activity_result, "check_system_activity")
    analysis_ok = _validate_tool_result(analysis_result, "analyze_evidence")
    tools_succeeded = sum([log_ok, activity_ok, analysis_ok])

    # --- Case A: all tools failed ---
    if tools_succeeded == 0:
        return {
            "success": False,
            "status": "error",
            "error": "Investigation tools returned no results.",
            "target_ip": target_ip or "unknown",
            "query": query,
            "evidence_complete": False,
            "tools_used": [],
            "errors": {
                "log_search": log_error,
                "system_activity": activity_error,
                "analysis": analysis_error,
            },
        }

    # --- Case B: partial evidence ---
    evidence_complete = tools_succeeded == 3

    # Step 4: Build risk indicators from tool results.
    # When a specific target was requested but analysis failed (e.g.
    # unsupported IP), do NOT fabricate risk from raw system-wide data —
    # that would produce misleading LOW risk for the wrong target.
    # Step 4: Build risk indicators.
    # Risk scoring REQUIRES target-specific correlated evidence from
    # analyze_evidence().  Without it, risk is UNKNOWN — we must NOT
    # fabricate target-specific risk from raw system-wide log/activity
    # data, as that would produce misleading risk assessments for the
    # wrong target.
    risk_indicators = {}
    target_analysis_missing = not analysis_ok

    if analysis_ok and isinstance(analysis_result, dict):
        raw_indicators = analysis_result.get("risk_indicators")
        if isinstance(raw_indicators, dict):
            risk_indicators = dict(raw_indicators)
            # Override source_ip with actual target — analysis may have
            # a hardcoded value.
            if target_ip and risk_indicators.get("source_ip") != target_ip:
                risk_indicators["source_ip"] = target_ip

    # Step 5: Compute risk score with exception handling
    risk_score = None
    risk_score_error = None
    try:
        risk_score = compute_risk_score(risk_indicators, KNOWN_BAD_IPS)
    except Exception as exc:
        risk_score_error = _sanitize_exception(exc)

    # When target-specific analysis is unavailable, the risk score
    # must be UNKNOWN — a score of 0/LOW from empty indicators would
    # be misleading.
    if target_analysis_missing:
        risk_score = {
            "score": None,
            "level": "UNKNOWN",
            "max_score": 100,
            "breakdown": {},
            "error": (
                "Target-specific correlated analysis is not available; "
                "risk cannot be assessed"
            ),
        }
        risk_score_error = None

    risk_score_failed = risk_score is None
    if risk_score_failed:
        # Risk scoring failed — do not fabricate a score or claim a complete
        # investigation. Risk assessment is a required investigation stage.
        risk_score = {
            "score": None,
            "level": "UNKNOWN",
            "max_score": 100,
            "breakdown": {},
            "error": risk_score_error or "risk assessment failed",
        }

    # Step 6: Build evidence summary
    evidence_lines = []
    findings = []

    if analysis_ok:
        findings = _sanitize_findings(analysis_result.get("findings", []))

    if log_ok:
        failed_logins = _safe_count(log_result.get("failed_logins"))
        successful_logins = _safe_count(log_result.get("successful_logins"))
        if failed_logins > 0:
            evidence_lines.append(
                f"{failed_logins} failed SSH login attempts"
                + (f" from {target_ip}" if target_ip else "")
            )
        if successful_logins > 0:
            evidence_lines.append(
                f"{successful_logins} successful login(s) after failures"
            )

    if activity_ok:
        suspicious_process_count = _safe_count(activity_result.get("suspicious_process_count"))
        unusual_connection_count = _safe_count(activity_result.get("unusual_connection_count"))
        if suspicious_process_count > 0:
            procs = _safe_list(activity_result.get("suspicious_processes"))
            names = []
            for p in procs[:3]:
                cmd = p.get("command", "unknown") if isinstance(p, dict) else "unknown"
                names.append(cmd)
            evidence_lines.append(
                f"Suspicious processes detected: {', '.join(names)}"
            )
        if unusual_connection_count > 0:
            evidence_lines.append(
                f"Unusual network connections: {unusual_connection_count} connection(s) to non-standard ports"
            )

    # Step 7: Generate recommendation based on risk level and evidence completeness
    level = risk_score.get("level", "UNKNOWN")
    recommendation = _generate_recommendation(
        level, evidence_complete, risk_score_available=not risk_score_failed
    )

    # Step 8: Determine tools used — only record tools that actually ran
    tools_used = []
    if log_ok:
        tools_used.append("search_security_logs")
    if activity_ok:
        tools_used.append("check_system_activity")
    if analysis_ok:
        tools_used.append("analyze_evidence")
    # Only claim risk_score succeeded if it actually returned a valid score
    if risk_score.get("score") is not None:
        tools_used.append("risk_score")

    if risk_score_failed:
        evidence_complete = False

    return {
        "success": False if risk_score_failed else True,
        "status": "error" if risk_score_failed else ("complete" if evidence_complete else "partial"),
        "evidence_complete": evidence_complete,
        "query": query,
        "target_ip": target_ip or "unknown",
        "severity": level,
        "risk_score": risk_score,
        "findings": findings,
        "evidence": evidence_lines,
        "tools_used": tools_used,
        "recommendation": recommendation,
        "containment_allowed": (
            not risk_score_failed and evidence_complete and risk_score.get("score") is not None
        ),
        "tool_results": {
            "authentication_logs": _sanitize_tool_result(log_result),
            "system_activity": _sanitize_tool_result(activity_result),
            "correlated_analysis": _sanitize_tool_result(analysis_result),
        },
        "errors": {
            "log_search": log_error,
            "system_activity": activity_error,
            "analysis": analysis_error,
        },
    }


def _generate_recommendation(
    level: str, evidence_complete: bool, risk_score_available: bool = True
) -> str:
    """Generate a human-readable recommendation based on risk level.

    When evidence is incomplete, recommendations are always cautious
    regardless of the computed risk level — we cannot make confident
    containment claims without full evidence.
    """
    if not risk_score_available:
        return (
            "Risk assessment could not be completed. Further investigation "
            "and verification are required before any containment action. "
            "Do not rely on an unavailable risk score."
        )

    if not evidence_complete:
        return (
            "Evidence collection was incomplete. Further investigation "
            "and verification are recommended before any containment "
            "action. Do not rely on this risk assessment alone."
        )

    if level == "CRITICAL":
        return (
            "Immediate containment recommended. Block source IP, isolate "
            "affected host, and escalate to incident response team."
        )
    elif level == "HIGH":
        return (
            "Containment recommended. Block source IP and review "
            "affected systems for compromise. Multiple strong "
            "incident indicators present."
        )
    elif level == "MEDIUM":
        return (
            "Enhanced monitoring recommended. Continue observing "
            "the source IP and review authentication policies. "
            "Some suspicious signals detected."
        )
    else:
        return (
            "No immediate action required. Continue normal "
            "monitoring. Indicators are below action thresholds."
        )


def _sanitize_tool_result(result: dict | None) -> dict:
    """Return a safe copy of a tool result for API response.

    Handles None, non-dict inputs, and only includes pre-approved
    safe fields.  Never exposes raw logs, credentials, paths, or
    arbitrary tool output.
    """
    if not isinstance(result, dict):
        return {"available": False}

    safe = {"available": True}
    safe_keys = (
        "success", "failed_logins", "successful_logins",
        "match_count", "process_count", "suspicious_process_count",
        "unusual_connection_count", "source_ip", "incident_id",
    )
    for key in safe_keys:
        if key in result:
            val = result[key]
            # Ensure safe types
            if key in ("failed_logins", "successful_logins", "match_count",
                       "process_count", "suspicious_process_count",
                       "unusual_connection_count"):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    val = 0
            elif key == "success":
                val = bool(val)
            elif key in ("source_ip", "incident_id"):
                if not isinstance(val, str):
                    val = str(val) if val is not None else ""
            safe[key] = val

    # findings: include only if present and is a list of strings
    if "findings" in result and isinstance(result["findings"], list):
        safe["findings"] = [
            str(f) for f in result["findings"] if isinstance(f, str)
        ][:_MAX_FINDINGS]

    return safe


if __name__ == "__main__":
    import json
    query = sys.argv[1] if len(sys.argv) > 1 else "Investigate suspicious activity from 10.0.0.25"
    result = run_investigation(query)
    print(json.dumps(result, indent=2))

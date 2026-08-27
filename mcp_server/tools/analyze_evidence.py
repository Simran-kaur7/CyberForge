"""Correlate authentication, process, and network evidence for an incident.

Both evidence sources (auth logs and system activity) are required for
a successful correlation.  If either is unavailable or malformed the
analyzer returns ``success=False`` so downstream consumers cannot
mistake partial data for a completed investigation.

The ``target_ip`` parameter scopes the analysis to the requested target.
When omitted the tool falls back to the legacy demo IP ``10.0.0.25``.
"""

import json

try:
    from .search_security_logs import search_security_logs
    from .check_system_activity import check_system_activity
except ImportError:
    # Preserve direct execution: ``python mcp_server/tools/analyze_evidence.py``.
    from search_security_logs import search_security_logs
    from check_system_activity import check_system_activity


# The only IP for which the demo dataset contains correlated evidence.
_DEMO_SOURCE_IP = "10.0.0.25"


def _coerce_evidence_count(value):
    """Return a non-negative integer for a trustworthy evidence count.

    Integer values and integer-like strings/floats are accepted.  Booleans,
    negative values, mappings, nulls, and malformed strings are rejected so
    bad evidence can never be silently treated as zero.
    """
    if isinstance(value, bool) or value is None:
        return None

    if isinstance(value, int):
        return value if value >= 0 else None

    if isinstance(value, float):
        if value.is_integer() and value >= 0:
            return int(value)
        return None

    if isinstance(value, str):
        text = value.strip()
        if not text or not text.isdigit():
            return None
        try:
            return int(text)
        except (ValueError, TypeError):
            return None

    return None


def _is_valid_evidence(result: dict, required_keys: tuple) -> bool:
    """Return True only when required evidence fields are present and valid."""
    if not isinstance(result, dict):
        return False
    if not result.get("success"):
        return False

    # Every numeric evidence field used by the correlation logic must be
    # present and safely convertible.  A malformed value invalidates the
    # entire source instead of being coerced into a misleading zero.
    for key in required_keys:
        if key not in result:
            return False
        if _coerce_evidence_count(result[key]) is None:
            return False

    return True


def analyze_evidence(target_ip: str | None = None) -> dict:
    """Correlate authentication, process, and network evidence.

    Parameters
    ----------
    target_ip:
        The IP address the caller is investigating.  When *None* the
        legacy demo value ``10.0.0.25`` is used.

    Returns
    -------
    dict
        ``success=True`` **only** when both dependency tools return
        valid evidence *and* the requested ``target_ip`` matches the
        demo scenario IP.  For any other target the analyzer returns
        ``success=False`` with a ``"not_supported"`` reason so callers
        never mistake demo evidence for another IP's evidence.

    .. note::

        The underlying ``search_security_logs`` call is always made
        against ``_DEMO_SOURCE_IP`` because the synthetic log file
        only contains entries for that address.  Making the log search
        target-aware would require a different evidence dataset and is
        out of scope.
    """

    effective_ip = target_ip or _DEMO_SOURCE_IP

    auth_errors: list[str] = []
    activity_errors: list[str] = []

    try:
        auth = search_security_logs(_DEMO_SOURCE_IP)
    except Exception as exc:
        auth = None
        auth_errors.append(type(exc).__name__)

    try:
        activity = check_system_activity()
    except Exception as exc:
        activity = None
        activity_errors.append(type(exc).__name__)

    # ---- validate both tools returned usable evidence ----
    auth_ok = _is_valid_evidence(
        auth, ("failed_logins", "successful_logins", "match_count")
    )
    activity_ok = _is_valid_evidence(
        activity,
        ("suspicious_process_count", "unusual_connection_count", "process_count"),
    )

    # Both are required — one partial source is not enough for
    # correlated analysis.
    if not (auth_ok and activity_ok):
        missing = []
        if not auth_ok:
            missing.append("authentication logs")
        if not activity_ok:
            missing.append("system activity")
        return {
            "success": False,
            "error": f"Evidence dependencies unavailable: {', '.join(missing)}",
            "findings": [],
            "risk_indicators": {},
        }

    # ---- target scope check ----
    # The only source_ip we can produce evidence for is the demo IP.
    # If the caller asked for a different target, refuse to return
    # evidence that does not belong to that target.
    if effective_ip != _DEMO_SOURCE_IP:
        return {
            "success": False,
            "error": (
                f"Correlated evidence is only available for the demo target "
                f"({_DEMO_SOURCE_IP}), not for {effective_ip}"
            ),
            "findings": [],
            "risk_indicators": {},
        }

    # ---- safe value extraction ----
    # Validation above guarantees these are trustworthy non-negative counts.
    # Keep the conversion defensive so ValueError/TypeError can never escape
    # from analyze_evidence() if a dependency changes unexpectedly.
    try:
        failed_logins = _coerce_evidence_count(auth["failed_logins"])
        successful_logins = _coerce_evidence_count(auth["successful_logins"])
        suspicious_process_count = _coerce_evidence_count(
            activity["suspicious_process_count"]
        )
        unusual_connection_count = _coerce_evidence_count(
            activity["unusual_connection_count"]
        )
    except (KeyError, TypeError, ValueError):
        return {
            "success": False,
            "error": "Evidence values are invalid",
            "findings": [],
            "risk_indicators": {},
        }

    if any(
        value is None
        for value in (
            failed_logins,
            successful_logins,
            suspicious_process_count,
            unusual_connection_count,
        )
    ):
        return {
            "success": False,
            "error": "Evidence values are invalid",
            "findings": [],
            "risk_indicators": {},
        }

    findings: list[str] = []

    if failed_logins >= 20:
        findings.append("High volume of failed SSH authentication attempts.")

    if successful_logins > 0:
        findings.append("Successful SSH login occurred after repeated failures.")

    if suspicious_process_count > 0:
        findings.append("Suspicious process detected after successful login.")

    if unusual_connection_count > 0:
        findings.append("Unusual network connection to port 4444 detected.")

    risk_indicators = {
        "failed_attempts": failed_logins,
        "successful_suspicious_login": successful_logins > 0,
        "suspicious_process": suspicious_process_count > 0,
        "unusual_connection": unusual_connection_count > 0,
        "source_ip": _DEMO_SOURCE_IP,
    }

    return {
        "success": True,
        "incident_id": "INC-1024",
        "source_ip": _DEMO_SOURCE_IP,
        "findings": findings,
        "risk_indicators": risk_indicators,
    }


if __name__ == "__main__":
    import sys as _sys

    ip = _sys.argv[1] if len(_sys.argv) > 1 else None
    print(json.dumps(analyze_evidence(target_ip=ip), indent=2))

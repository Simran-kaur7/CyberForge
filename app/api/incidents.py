from fastapi import APIRouter, HTTPException

from app.sdk_client import (
    ToolTimeoutError,
    analyze_evidence,
    check_system_activity,
    create_session,
    find_session_by_incident,
    list_sessions,
    search_security_logs,
)


router = APIRouter(prefix="/api", tags=["incidents"])


def _require_successful_tool_result(result: object, tool_name: str) -> dict:
    """Return a valid tool response or fail the investigation cleanly."""
    if not isinstance(result, dict) or not result.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"{tool_name} did not return usable investigation evidence.",
        )
    return result


@router.get("/sessions")
def get_sessions():
    """List all investigation sessions."""
    return list_sessions()


@router.get("/incidents/{incident_id}/investigate")
def investigate_incident(incident_id: str):
    if incident_id != "INC-1024":
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} is not available in the demo evidence set.",
        )

    try:
        analysis = _require_successful_tool_result(
            analyze_evidence(), "Evidence analysis"
        )
        source_ip = analysis.get("source_ip")

        if not source_ip:
            raise HTTPException(
                status_code=502,
                detail="Evidence analysis did not return a source IP.",
            )

        logs = _require_successful_tool_result(
            search_security_logs(source_ip), "Security log search"
        )
        activity = _require_successful_tool_result(
            check_system_activity(), "System activity check"
        )

    except HTTPException:
        raise

    except ToolTimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="Security investigation tool timed out.",
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=502,
            detail="Security investigation tool failed.",
        ) from exc

    # Create or reuse a local session for this incident
    existing = find_session_by_incident(incident_id)
    if existing:
        local_session = existing
    else:
        local_session = create_session(incident_id, evidence_snapshot=analysis)

    local_session_id = local_session["id"]

    # Optionally create a TrueForge session and store its ID
    trueforge_session_id = None
    try:
        import os
        import json as _json
        import urllib.request as _req
        tf_url = os.environ.get("TRUEFORGE_URL", "http://localhost:8790")
        payload = _json.dumps({
            "title": f"Investigation: {incident_id}",
            "metadata": {"incident_id": incident_id, "local_session_id": local_session_id},
        }).encode()
        r = _req.urlopen(
            _req.Request(
                f"{tf_url}/api/v1/sessions",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            ),
            timeout=10,
        )
        tf_resp = _json.loads(r.read().decode())
        trueforge_session_id = tf_resp.get("id") or tf_resp.get("data", {}).get("id")
        # Persist the TrueForge session ID back to our local session
        if trueforge_session_id:
            from app.sdk_client import update_session
            update_session(local_session_id, trueforge_session_id=trueforge_session_id)
    except Exception:
        pass  # TrueForge unavailable, local-only mode

    return {
        "success": True,
        "incident_id": incident_id,
        "session_id": local_session_id,
        "trueforge_session_id": trueforge_session_id,
        "analysis": analysis,
        "authentication": logs,
        "system_activity": activity,
    }

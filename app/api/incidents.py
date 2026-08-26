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

    # Create or reuse a session for this incident
    existing = find_session_by_incident(incident_id)
    if existing:
        session_id = existing["id"]
    else:
        session = create_session(incident_id, evidence_snapshot=analysis)
        session_id = session["id"]

    return {
        "success": True,
        "incident_id": incident_id,
        "session_id": session_id,
        "analysis": analysis,
        "authentication": logs,
        "system_activity": activity,
    }

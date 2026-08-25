from fastapi import APIRouter, HTTPException

from app.sdk_client import (
    ToolTimeoutError,
    analyze_evidence,
    check_system_activity,
    search_security_logs,
)


router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("/{incident_id}/investigate")
def investigate_incident(incident_id: str):
    if incident_id != "INC-1024":
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} is not available in the demo evidence set.",
        )

    try:
        analysis = analyze_evidence()
        source_ip = analysis.get("source_ip")

        if not source_ip:
            raise HTTPException(
                status_code=502,
                detail="Evidence analysis did not return a source IP.",
            )

        logs = search_security_logs(source_ip)
        activity = check_system_activity()

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

    return {
        "success": True,
        "incident_id": incident_id,
        "analysis": analysis,
        "authentication": logs,
        "system_activity": activity,
    }
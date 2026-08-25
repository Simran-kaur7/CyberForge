from fastapi import APIRouter, HTTPException

from app.sdk_client import (
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

    analysis = analyze_evidence()
    source_ip = analysis.get("source_ip", "")

    logs = search_security_logs(source_ip)
    activity = check_system_activity()

    return {
        "success": True,
        "incident_id": incident_id,
        "analysis": analysis,
        "authentication": logs,
        "system_activity": activity,
    }

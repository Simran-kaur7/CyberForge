import logging
import urllib.error

try:
    from fastapi import APIRouter
except ImportError:  # pragma: no cover - keeps local tests working without FastAPI
    class APIRouter:
        def __init__(self, *args, **kwargs):
            self.routes = []

        def _decorator(self, *args, **kwargs):
            def wrapper(func):
                self.routes.append((args, kwargs, func))
                return func
            return wrapper

        get = _decorator

from app.api.approvals import HTTPException

from app.sdk_client import (
    ToolTimeoutError,
    analyze_evidence,
    check_system_activity,
    create_session,
    find_session_by_incident,
    list_sessions,
    search_security_logs,
    update_session,
)

logger = logging.getLogger(__name__)

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

    # Keep session metadata consistent with actual investigation
    update_result = update_session(
        local_session["id"],
        evidence_snapshot=analysis,
    )
    if not update_result.get("success"):
        # Session persistence is required because the investigation result is
        # later used as the authoritative local session for approval actions.
        # Do not report a complete investigation when that persistence failed.
        logger.warning(
            "Failed to update session %s metadata: %s",
            local_session["id"],
            update_result.get("error", "unknown"),
        )
        raise HTTPException(
            status_code=503,
            detail="Investigation session could not be persisted.",
        )

    local_session_id = local_session["id"]

    # Reuse existing TrueForge session if already linked, otherwise create new
    trueforge_session_id = local_session.get("trueforge_session_id")
    if not trueforge_session_id:
        try:
            import os
            import json as _json
            import urllib.request as _req
            from app.sdk_client import persist_trueforge_session_id
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
            new_tf_id = tf_resp.get("id") or tf_resp.get("data", {}).get("id")
            if new_tf_id:
                # Compare-and-set: only persist if still None
                cas_result = persist_trueforge_session_id(local_session_id, new_tf_id)
                # Use the winning ID (another request may have set it first)
                trueforge_session_id = cas_result.get("trueforge_session_id", new_tf_id)
        except (urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError) as exc:
            # Expected: TrueForge genuinely unavailable — operate in local-only mode
            logger.info("TrueForge unavailable for session %s: %s", local_session_id, type(exc).__name__)
        except (ValueError, KeyError) as exc:
            # Unexpected: TrueForge returned something we can't parse
            logger.warning("Unexpected TrueForge response for session %s: %s", local_session_id, type(exc).__name__)
        except Exception as exc:
            # Truly unexpected error — log so it doesn't disappear silently
            logger.error("Unhandled TrueForge error for session %s: %s", local_session_id, exc, exc_info=True)

    return {
        "success": True,
        "incident_id": incident_id,
        "session_id": local_session_id,
        "trueforge_session_id": trueforge_session_id,
        "analysis": analysis,
        "authentication": logs,
        "system_activity": activity,
    }

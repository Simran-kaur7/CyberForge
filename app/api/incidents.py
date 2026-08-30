import json
import logging
import os
import urllib.error
import urllib.request

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
    claim_orphan_session,
    create_session,
    find_session_by_incident,
    list_sessions,
    persist_trueforge_session_id,
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

    # Create or reuse a local session for this incident.
    # Try exact target_ip match first; then atomically claim any orphan
    # (session with same incident_id but no target_ip) to prevent races
    # where two concurrent investigations claim the same orphan.
    resolved_target = source_ip or None
    local_session = None

    if resolved_target:
        # Exact match first
        local_session = find_session_by_incident(incident_id, target_ip=resolved_target)

        if not local_session:
            # Atomically claim an orphan session (no target_ip)
            local_session = claim_orphan_session(
                incident_id, resolved_target,
                evidence_snapshot=analysis,
            )

    if not local_session:
        local_session = create_session(
            incident_id,
            evidence_snapshot=analysis,
            **({"target_ip": resolved_target} if resolved_target else {}),
        )

    # Keep session metadata consistent with actual investigation.
    # Supersede any stale approval: the evidence and risk are being
    # replaced, so an approval bound to the previous run's TrueForge
    # tool call must not remain decidable.
    try:
        update_result = update_session(
            local_session["id"],
            evidence_snapshot=analysis,
            supersede_stale_approval=True,
            **({"target_ip": resolved_target} if resolved_target else {}),
        )
    except RuntimeError:
        raise HTTPException(
            status_code=409,
            detail="An approval operation is in progress for this incident; retry after it completes.",
        )

    if not update_result.get("success"):
        if update_result.get("approval_in_progress"):
            raise HTTPException(
                status_code=409,
                detail="An approval operation is in progress for this incident; retry after it completes.",
            )
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

    # Reuse an existing TrueForge session when this CyberForge session
    # already has one. Otherwise create a new TrueForge inline session.
    #
    # CyberForge owns the incident -> TrueForge session association locally.
    # TrueForge's session-create API does not accept CyberForge-specific
    # "title" or "metadata" fields.
    trueforge_session_id = local_session.get("trueforge_session_id")

    if not trueforge_session_id:
        try:
            tf_url = os.environ.get(
                "TRUEFORGE_URL",
                "http://localhost:8790",
            ).rstrip("/")

            payload = json.dumps(
                {
                    "agent": {
                        "spec": {
                            "model": {
                                "name": os.environ.get(
                                    "TRUEFORGE_MODEL",
                                    "google-gemini/gemini-3-6-flash",
                                ),
                            },
                            "instructions": (
                                "You are a SOC incident-response agent for CyberForge."
                                "\n"
                                "INVESTIGATION WORKFLOW:"
                                "\n1. When asked to investigate an incident, dispatch two subagents in parallel:"
                                "\n   - Subagent A: Runs search_security_logs + analyze_evidence (authentication and correlation)"
                                "\n   - Subagent B: Runs check_system_activity (host process and network analysis)"
                                "\n2. Merge findings from both subagents into a single risk_indicators dict."
                                "\n3. Run risk_score.py in Code Mode (sandbox) using the merged indicators."
                                "\n4. Present findings, risk level, and recommended action to the analyst."
                                "\n5. If containment is recommended, request human approval before calling block_ip."
                                "\n"
                                "RULES:"
                                "\n- NEVER call block_ip without explicit human approval."
                                "\n- NEVER auto-contain, even with a CRITICAL risk score."
                                "\n- Always explain WHY each signal is suspicious before recommending action."
                                "\n- Use subagents for parallel evidence gathering â do not run tools sequentially."
                                "\n"
                                "SCORING (handled by risk_score.py in sandbox):"
                                "\n- failed_attempts (>=20): +20 points"
                                "\n- successful_suspicious_login: +25 points"
                                "\n- suspicious_process: +25 points"
                                "\n- unusual_connection: +20 points"
                                "\n- source_ip (if on known-bad list): +10 points"
                                "\n- Thresholds: 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL"
                            ),
                            "mcp_servers": [
                                {
                                    "name": "cyberforge-tools",
                                    "enable_tools": ["@all"],
                                    "require_approval_for_tools": ["block_ip"],
                                    "preload": False,
                                },
                            ],
                            "config": {
                                "iteration_limit": 100,
                                "sandbox": {
                                    "enabled": True,
                                    "file_downloads": True,
                                },
                                "dynamic_sub_agents": {
                                    "enabled": True,
                                },
                                "context_management": {
                                    "compaction": {
                                        "enabled": True,
                                    },
                                    "large_tool_response": {
                                        "enabled": True,
                                    },
                                },
                                "generative_ui": {
                                    "enabled": True,
                                },
                                "ask_user_questions": {
                                    "enabled": True,
                                },
                            },
                        },
                    },
                }
            ).encode("utf-8")

            response = urllib.request.urlopen(
                urllib.request.Request(
                    f"{tf_url}/api/v1/sessions",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=10,
            )

            tf_resp = json.loads(
                response.read().decode("utf-8")
            )

            new_tf_id = (
                tf_resp.get("id")
                or tf_resp.get("data", {}).get("id")
            )

            if not new_tf_id:
                raise RuntimeError(
                    "TrueForge created a session without returning an id."
                )

            # Persist the association locally. The local CyberForge session
            # remains the authoritative mapping between incident and
            # TrueForge session.
            cas_result = persist_trueforge_session_id(
                local_session_id,
                new_tf_id,
            )

            if not cas_result.get("success"):
                logger.warning(
                    "Failed to persist TrueForge session %s for CyberForge "
                    "session %s: %s",
                    new_tf_id,
                    local_session_id,
                    cas_result.get("error", "unknown"),
                )
            else:
                # Use the ID actually stored by the compare-and-set operation.
                # If another concurrent request won the race, this should be
                # the already-persisted TrueForge session ID.
                trueforge_session_id = cas_result.get(
                    "trueforge_session_id",
                    new_tf_id,
                )

                logger.info(
                    "Linked CyberForge session %s to TrueForge session %s",
                    local_session_id,
                    trueforge_session_id,
                )

        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            ConnectionError,
            TimeoutError,
        ) as exc:
            # TrueForge genuinely unavailable â retain local-only operation.
            logger.info(
                "TrueForge unavailable for session %s: %s",
                local_session_id,
                type(exc).__name__,
            )

        except (ValueError, KeyError) as exc:
            # TrueForge returned a response that could not be interpreted.
            logger.warning(
                "Unexpected TrueForge response for session %s: %s",
                local_session_id,
                type(exc).__name__,
            )

        except Exception as exc:
            # Keep the investigation endpoint alive, but do not silently hide
            # unexpected integration failures.
            logger.error(
                "Unhandled TrueForge error for session %s: %s",
                local_session_id,
                exc,
                exc_info=True,
            )

    return {
        "success": True,
        "incident_id": incident_id,
        "session_id": local_session_id,
        "trueforge_session_id": trueforge_session_id,
        "analysis": analysis,
        "authentication": logs,
        "system_activity": activity,
    }


from pathlib import Path

FIREWALL_FILE = Path(__file__).resolve().parent.parent.parent / 'mcp_server' / 'data' / 'simulated_firewall.json'


@router.get('/firewall')
def get_firewall_status():
    """Return the current blocked IPs from the simulated firewall.

    Only blocked_ips are returned  --  the event history grows unboundedly
    and is not needed by the frontend.
    """
    if not FIREWALL_FILE.exists():
        return {'blocked_ips': []}
    try:
        data = json.loads(FIREWALL_FILE.read_text(encoding='utf-8'))
        blocked = data.get('blocked_ips', [])
        return {
            'blocked_ips': blocked if isinstance(blocked, list) else [],
        }
    except (json.JSONDecodeError, OSError):
        # Do not silently return empty on transient read errors  -- 
        # let the caller see an empty list but log that it happened.
        return {'blocked_ips': []}

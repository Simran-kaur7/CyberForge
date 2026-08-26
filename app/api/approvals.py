"""
CyberForge Approval API — TrueForge native approval gate.

TrueForge create-turn returns an SSE stream. This module:
1. Sends turns (message or approval) via SSE-aware transport
2. Reads events until turn.done or tool.approval_required
3. Returns the terminal event as the response
Requires CYBERFORGE_API_KEY for containment decisions.
"""

import os
import json
import urllib.request
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional


router = APIRouter(prefix="/api/approvals", tags=["approvals"])

TRUEFORGE_URL = os.environ.get("TRUEFORGE_URL", "http://localhost:8790")
EXPECTED_API_KEY = os.environ.get("CYBERFORGE_API_KEY", "")


class ApprovalRequest(BaseModel):
    session_id: str
    trueforge_session_id: Optional[str] = None
    message: str = "Investigate and contain the incident"
    thread_id: Optional[str] = None


class DecisionRequest(BaseModel):
    session_id: str
    action_id: str
    tool_call_id: Optional[str] = None
    trueforge_session_id: Optional[str] = None
    thread_id: Optional[str] = None
    reason: Optional[str] = None


def _require_api_key(authorization: Optional[str] = Header(None)) -> str:
    if not EXPECTED_API_KEY:
        return "analyst"

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
        )

    token = authorization.replace("Bearer ", "").strip()

    if token != EXPECTED_API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key",
        )

    return "analyst"


def _tf_post_sse(path: str, body: dict) -> dict:
    """POST to TrueForge and preserve approval metadata from the SSE stream."""
    url = f"{TRUEFORGE_URL}{path}"
    data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            content_type = resp.headers.get("Content-Type", "")

            if "event-stream" in content_type or "text/plain" in content_type:
                last_event = {}
                approval_event = None

                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    if not line.startswith("data: "):
                        continue

                    payload = line[6:]
                    if not payload.strip():
                        continue

                    try:
                        event = json.loads(payload)
                    except json.JSONDecodeError:
                        continue

                    event_type = event.get("type", "")
                    if event_type == "tool.approval_required":
                        approval_event = event

                    last_event = event

                    if event_type in ("turn.done", "turn.failed", "error"):
                        break

                if not last_event and approval_event:
                    last_event = approval_event

                result = dict(last_event) if last_event else {"status": "ok"}

                if approval_event:
                    tool_calls = approval_event.get("tool_calls") or []
                    if isinstance(tool_calls, dict):
                        tool_calls = [tool_calls]

                    tool_call_id = None
                    if tool_calls and isinstance(tool_calls[0], dict):
                        tool_call_id = tool_calls[0].get("id") or tool_calls[0].get("tool_call_id")

                    result["approval_required"] = approval_event
                    result["tool_call_id"] = tool_call_id
                    result["thread_id"] = (
                        approval_event.get("thread_id")
                        or (tool_calls[0].get("thread_id") if tool_calls and isinstance(tool_calls[0], dict) else None)
                    )

                return result

            raw = resp.read().decode()
            if not raw.strip():
                return {"status": "ok"}
            return json.loads(raw)

    except json.JSONDecodeError as exc:
        raise RuntimeError("TrueForge returned invalid JSON") from exc
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"TrueForge returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("Cannot reach TrueForge") from exc


def _tf_get(path: str) -> dict:
    url = f"{TRUEFORGE_URL}{path}"

    req = urllib.request.Request(
        url,
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode()

            if not raw.strip():
                return {}

            return json.loads(raw)

    except json.JSONDecodeError:
        raise RuntimeError("TrueForge returned invalid JSON")

    except urllib.error.HTTPError:
        raise RuntimeError("TrueForge returned an error")

    except urllib.error.URLError:
        raise RuntimeError("Cannot reach TrueForge")


def _extract_identity_values(value) -> dict[str, set[str]]:
    """Collect known CyberForge identity fields from a TrueForge object."""
    found = {"local_session_id": set(), "incident_id": set()}

    def walk(obj):
        if isinstance(obj, dict):
            for key, item in obj.items():
                if key in ("local_session_id", "cyberforge_session_id") and isinstance(item, str):
                    found["local_session_id"].add(item)
                elif key in ("incident_id", "local_incident_id") and isinstance(item, str):
                    found["incident_id"].add(item)
                if isinstance(item, (dict, list)):
                    walk(item)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    walk(item)

    walk(value)
    return found


def _verify_trueforge_session_ownership(
    tf_session_id: str,
    local_session_id: str,
    incident_id: str,
) -> dict:
    """Verify a caller-supplied TrueForge session belongs to this incident."""
    session = _tf_get(f"/api/v1/sessions/{tf_session_id}")
    identities = _extract_identity_values(session)

    local_match = local_session_id in identities["local_session_id"]
    incident_match = incident_id in identities["incident_id"]

    if not (local_match or incident_match):
        raise HTTPException(
            status_code=409,
            detail="TrueForge session does not belong to this CyberForge incident",
        )

    return session


@router.post("/request")
def request_containment_approval(
    body: ApprovalRequest,
    authorization: Optional[str] = Header(None),
):
    """Create a local approval and bind it to the verified TrueForge call."""
    analyst = _require_api_key(authorization)

    try:
        from app.sdk_client import (
            request_approval,
            get_session,
            set_approval_tool_call_id,
            persist_trueforge_session_id,
            release_forwarding_claim,
            release_request_claim,
        )

        session = get_session(body.session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        local_session_id = body.session_id
        actual_incident_id = session["incident_id"]
        stored_tf_session_id = session.get("trueforge_session_id")

        if body.trueforge_session_id and stored_tf_session_id:
            if body.trueforge_session_id != stored_tf_session_id:
                raise HTTPException(
                    status_code=409,
                    detail="trueforge_session_id does not belong to this action",
                )

        tf_session_id = stored_tf_session_id or body.trueforge_session_id

        if body.trueforge_session_id and not stored_tf_session_id:
            _verify_trueforge_session_ownership(
                body.trueforge_session_id,
                local_session_id,
                actual_incident_id,
            )

            persisted = persist_trueforge_session_id(
                local_session_id,
                body.trueforge_session_id,
            )

            if not persisted.get("success"):
                raise HTTPException(
                    status_code=409,
                    detail=persisted.get(
                        "error",
                        "Session update failed",
                    ),
                )

            tf_session_id = persisted["trueforge_session_id"]

        result = request_approval(
            local_session_id,
            "block_ip",
            {
                "incident_id": actual_incident_id,
                "message": body.message,
                "trueforge_session_id": tf_session_id,
            },
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=409,
                detail=result.get("error", "Request failed"),
            )

        action_id = result["action_id"]

        tf_event = None
        tool_call_id = None
        thread_id = None

        if tf_session_id:
            try:
                tf_event = _tf_post_sse(
                    f"/api/v1/sessions/{tf_session_id}/turns",
                    {
                        "input": [
                            {
                                "type": "user.message",
                                "content": body.message,
                            }
                        ]
                    },
                )

                tool_call_id = tf_event.get("tool_call_id")
                thread_id = tf_event.get("thread_id")

            except RuntimeError as exc:
                # Release request claim upon failure so concurrent retries can run
                release_request_claim(local_session_id, action_id)

                # Keep detailed exception context in server logs only.
                print(
                    f"TrueForge forward failed for session "
                    f"{local_session_id}: {exc}"
                )

                # Keep the local approval pending so the same
                # request can retry the TrueForge forward.
                return {
                    "success": True,
                    "action_id": action_id,
                    "session_id": local_session_id,
                    "trueforge_session_id": tf_session_id,
                    "tool_call_id": None,
                    "thread_id": None,
                    "analyst": analyst,
                    "trueforge_event": None,
                    "trueforge_forward_error": "Failed to forward request to TrueForge; please retry.",
                    "retryable": True,
                }

        late_forward = None

        if tool_call_id:
            cas_result = set_approval_tool_call_id(
                local_session_id,
                action_id,
                tool_call_id,
                thread_id=thread_id,
            )

            if not cas_result.get("success"):
                raise HTTPException(
                    status_code=409,
                    detail=cas_result.get(
                        "error",
                        "Could not bind tool call",
                    ),
                )

            if cas_result.get("pending_decision"):
                late_forward = cas_result

        if late_forward and tf_session_id and tool_call_id:
            decision = late_forward["pending_decision"]
            decided_by = late_forward.get("decided_by", "analyst")

            approval_input = {
                "type": "user.tool_approval",
                "tool_call_id": tool_call_id,
                "approval": (
                    {"status": "allow"}
                    if decision == "approved"
                    else {
                        "status": "deny",
                        "reason": f"Rejected by {decided_by}",
                    }
                ),
            }

            if thread_id:
                approval_input["thread_id"] = thread_id

            try:
                _tf_post_sse(
                    f"/api/v1/sessions/{tf_session_id}/turns",
                    {"input": [approval_input]},
                )

            except RuntimeError as exc:
                release_forwarding_claim(
                    local_session_id,
                    action_id,
                    str(exc),
                )

                return {
                    "success": True,
                    "action_id": action_id,
                    "session_id": local_session_id,
                    "trueforge_session_id": tf_session_id,
                    "tool_call_id": tool_call_id,
                    "thread_id": thread_id,
                    "analyst": analyst,
                    "trueforge_event": tf_event,
                    "late_forward_failed": True,
                    "retryable": True,
                }

        return {
            "success": True,
            "action_id": action_id,
            "session_id": local_session_id,
            "trueforge_session_id": tf_session_id,
            "tool_call_id": tool_call_id,
            "thread_id": thread_id,
            "analyst": analyst,
            "trueforge_event": tf_event,
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Approval request failed: {exc}",
        )


def _forward_decision(
    tf_session_id: str,
    tool_call_id: str,
    decision: str,
    reason: Optional[str],
    thread_id: Optional[str],
) -> dict:
    approval_input = {
        "type": "user.tool_approval",
        "tool_call_id": tool_call_id,
        "approval": (
            {"status": "allow"}
            if decision == "approved"
            else {
                "status": "deny",
                "reason": reason or "Rejected by analyst",
            }
        ),
    }
    if thread_id:
        approval_input["thread_id"] = thread_id

    return _tf_post_sse(
        f"/api/v1/sessions/{tf_session_id}/turns",
        {"input": [approval_input]},
    )


def _decide_containment(
    body: DecisionRequest,
    analyst: str,
    decision: str,
) -> dict:
    from app.sdk_client import (
        prepare_decision,
        complete_decision,
        fail_decision,
        get_session,
    )

    prepared = prepare_decision(
        body.session_id,
        body.action_id,
        decision,
        analyst,
        expected_tool_call_id=body.tool_call_id,
        expected_trueforge_session_id=body.trueforge_session_id,
    )
    if not prepared.get("success"):
        raise HTTPException(status_code=409, detail=prepared.get("error", "Decision failed"))

    token = prepared["token"]
    tf_session_id = prepared.get("trueforge_session_id")
    tool_call_id = prepared.get("tool_call_id")
    stored_thread_id = prepared.get("thread_id")

    if body.thread_id and stored_thread_id and body.thread_id != stored_thread_id:
        fail_decision(
            body.session_id,
            body.action_id,
            token,
            "thread_id does not belong to this action",
        )
        raise HTTPException(status_code=409, detail="thread_id does not belong to this action")

    thread_id = stored_thread_id or body.thread_id

    # A TrueForge-bound action must be delivered upstream before it becomes
    # terminal locally. Without an upstream association, local-only mode remains valid.
    if tf_session_id and not tool_call_id:
        fail_decision(
            body.session_id,
            body.action_id,
            token,
            "No authoritative tool_call_id is stored for this action",
        )
        raise HTTPException(
            status_code=502,
            detail="TrueForge approval call is not yet bound to this action; retry",
        )

    tf_event = None
    if tf_session_id and tool_call_id:
        try:
            tf_event = _forward_decision(
                tf_session_id,
                tool_call_id,
                decision,
                body.reason,
                thread_id,
            )
        except RuntimeError as exc:
            fail_decision(
                body.session_id,
                body.action_id,
                token,
                str(exc),
            )
            raise HTTPException(
                status_code=502,
                detail=f"TrueForge decision forwarding failed: {exc}",
            )

    completed = complete_decision(
        body.session_id,
        body.action_id,
        token,
    )
    if not completed.get("success"):
        raise HTTPException(status_code=409, detail=completed.get("error", "Decision finalization failed"))

    return {
        "success": True,
        "action_id": body.action_id,
        "status": completed["status"],
        "analyst": analyst,
        "trueforge_event": tf_event,
    }


@router.post("/approve")
def approve_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """Approve only after a TrueForge-bound decision is successfully forwarded."""
    analyst = _require_api_key(authorization)
    try:
        return _decide_containment(body, analyst, "approved")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Approval failed")


@router.post("/reject")
def reject_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """Reject only after a TrueForge-bound decision is successfully forwarded."""
    analyst = _require_api_key(authorization)
    try:
        return _decide_containment(body, analyst, "rejected")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Rejection failed")


@router.get("/pending")
def get_pending_approvals():
    """List sessions with pending approval state from TrueForge."""
    try:
        sessions = _tf_get("/api/v1/sessions")

        session_list = (
            sessions.get("data", sessions)
            if isinstance(sessions, dict)
            else sessions
        )

        pending = []

        if isinstance(session_list, list):
            for s in session_list:
                state = s.get("state") or {}
                actions = (
                    state.get("required_actions")
                    or []
                )

                if actions:
                    pending.append(
                        {
                            "session_id": s.get("id"),
                            "title": s.get("title"),
                            "required_actions": actions,
                        }
                    )

        return {
            "count": len(pending),
            "approvals": pending,
        }

    except RuntimeError:
        return {
            "count": 0,
            "approvals": [],
            "warning": "TrueForge unavailable",
        }
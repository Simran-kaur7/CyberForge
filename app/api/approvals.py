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
    session_id: str  # CyberForge local session ID
    trueforge_session_id: Optional[str] = None  # TrueForge session ID (if known)
    message: str = "Investigate and contain the incident"
    thread_id: Optional[str] = None


class DecisionRequest(BaseModel):
    session_id: str  # CyberForge local session ID
    action_id: str  # CyberForge local action ID
    tool_call_id: Optional[str] = None  # TrueForge tool_call_id (if known)
    trueforge_session_id: Optional[str] = None  # TrueForge session ID (if known)
    thread_id: Optional[str] = None
    reason: Optional[str] = None


def _require_api_key(authorization: Optional[str] = Header(None)) -> str:
    if not EXPECTED_API_KEY:
        return "analyst"
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.replace("Bearer ", "").strip()
    if token != EXPECTED_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return "analyst"


def _tf_post_sse(path: str, body: dict) -> dict:
    """
    POST to TrueForge and consume the SSE stream.
    Returns the last meaningful event (turn.done or error).
    """
    url = f"{TRUEFORGE_URL}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            content_type = resp.headers.get("Content-Type", "")

            # If it's SSE, read the event stream
            if "event-stream" in content_type or "text/plain" in content_type:
                last_event = {}
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data: "):
                        payload = line[6:]
                        if not payload.strip():
                            continue
                        try:
                            event = json.loads(payload)
                        except json.JSONDecodeError:
                            continue
                        last_event = event
                        # Stop on terminal events
                        etype = event.get("type", "")
                        if etype in ("turn.done", "turn.failed", "error"):
                            break
                return last_event if last_event else {"status": "ok"}

            # Otherwise it's regular JSON
            raw = resp.read().decode()
            if not raw.strip():
                return {"status": "ok"}
            return json.loads(raw)

    except json.JSONDecodeError:
        raise RuntimeError("TrueForge returned invalid JSON")
    except urllib.error.HTTPError:
        raise RuntimeError("TrueForge returned an error")
    except urllib.error.URLError:
        raise RuntimeError("Cannot reach TrueForge")


def _tf_get(path: str) -> dict:
    url = f"{TRUEFORGE_URL}{path}"
    req = urllib.request.Request(url, method="GET")
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


@router.post("/request")
def request_containment_approval(
    body: ApprovalRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Request human approval for a containment action.
    Uses local SDK state machine as primary store.
    Optionally forwards to TrueForge if available.
    """
    analyst = _require_api_key(authorization)
    try:
        from app.sdk_client import request_approval, get_session

        # Resolve IDs: local for CyberForge, TrueForge for upstream
        session = get_session(body.session_id)
        local_session_id = body.session_id
        tf_session_id = body.trueforge_session_id
        if not tf_session_id and session:
            tf_session_id = session.get("trueforge_session_id")

        actual_incident_id = session["incident_id"] if session else local_session_id
        result = request_approval(
            local_session_id, "block_ip",
            {
                "incident_id": actual_incident_id,
                "message": body.message,
                "trueforge_session_id": tf_session_id,
            }
        )
        if not result.get("success"):
            raise HTTPException(status_code=409, detail=result.get("error", "Request failed"))

        # Forward to TrueForge using the TRUEFORGE session ID (not local)
        tf_event = None
        tool_call_id = None
        if tf_session_id:
            try:
                tf_event = _tf_post_sse(
                    f"/api/v1/sessions/{tf_session_id}/turns",
                    {"input": [{"type": "user.message", "content": body.message}]},
                )
                tool_call_id = tf_event.get("tool_call_id") or tf_event.get("tool_call", {}).get("id")
            except RuntimeError:
                pass  # TrueForge unavailable

        # Persist tool_call_id in local session's approval state
        if tool_call_id:
            try:
                from app.sdk_client import update_session, get_session
                sess = get_session(local_session_id)
                if sess and sess.get("approval_state"):
                    sess["approval_state"]["tool_call_id"] = tool_call_id
                    update_session(local_session_id, approval_state=sess["approval_state"])
            except Exception:
                pass

        return {
            "success": True,
            "action_id": result["action_id"],
            "session_id": local_session_id,
            "trueforge_session_id": tf_session_id,
            "tool_call_id": tool_call_id,
            "analyst": analyst,
            "trueforge_event": tf_event,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Approval request failed")


@router.post("/approve")
def approve_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """Approve a pending tool call via local SDK + optional TrueForge."""
    analyst = _require_api_key(authorization)
    try:
        from app.sdk_client import approve_action, get_session

        # Local approval: use CyberForge action_id + session_id
        result = approve_action(body.session_id, body.action_id, analyst)
        if not result.get("success"):
            raise HTTPException(status_code=409, detail=result.get("error", "Approval failed"))

        # TrueForge approval: use tool_call_id + trueforge_session_id
        tf_event = None
        tf_session_id = body.trueforge_session_id
        tf_tool_call_id = body.tool_call_id
        if not tf_session_id:
            session = get_session(body.session_id)
            if session:
                tf_session_id = session.get("trueforge_session_id")
        if not tf_tool_call_id:
            session = get_session(body.session_id)
            if session and session.get("approval_state"):
                tf_tool_call_id = session["approval_state"].get("tool_call_id")

        if tf_session_id and tf_tool_call_id:
            try:
                approval_input = {
                    "type": "user.tool_approval",
                    "tool_call_id": tf_tool_call_id,
                    "approval": {"status": "allow"},
                }
                if body.thread_id:
                    approval_input["thread_id"] = body.thread_id
                tf_event = _tf_post_sse(
                    f"/api/v1/sessions/{tf_session_id}/turns",
                    {"input": [approval_input]},
                )
            except RuntimeError:
                pass

        return {
            "success": True, "action_id": body.action_id,
            "status": "approved", "analyst": analyst,
            "trueforge_event": tf_event,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Approval failed")


@router.post("/reject")
def reject_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """Reject a pending tool call via local SDK + optional TrueForge."""
    analyst = _require_api_key(authorization)
    try:
        from app.sdk_client import reject_action, get_session

        # Local rejection: use CyberForge action_id + session_id
        result = reject_action(body.session_id, body.action_id, analyst)
        if not result.get("success"):
            raise HTTPException(status_code=409, detail=result.get("error", "Rejection failed"))

        # TrueForge rejection: use tool_call_id + trueforge_session_id
        tf_event = None
        tf_session_id = body.trueforge_session_id
        tf_tool_call_id = body.tool_call_id
        if not tf_session_id:
            session = get_session(body.session_id)
            if session:
                tf_session_id = session.get("trueforge_session_id")
        if not tf_tool_call_id:
            session = get_session(body.session_id)
            if session and session.get("approval_state"):
                tf_tool_call_id = session["approval_state"].get("tool_call_id")

        if tf_session_id and tf_tool_call_id:
            try:
                reason = body.reason or f"Rejected by {analyst}"
                approval_input = {
                    "type": "user.tool_approval",
                    "tool_call_id": tf_tool_call_id,
                    "approval": {"status": "deny", "reason": reason},
                }
                if body.thread_id:
                    approval_input["thread_id"] = body.thread_id
                tf_event = _tf_post_sse(
                    f"/api/v1/sessions/{tf_session_id}/turns",
                    {"input": [approval_input]},
                )
            except RuntimeError:
                pass

        return {
            "success": True, "action_id": body.action_id,
            "status": "rejected", "analyst": analyst,
            "trueforge_event": tf_event,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Rejection failed")


@router.get("/pending")
def get_pending_approvals():
    """List sessions with pending approval state from TrueForge."""
    try:
        sessions = _tf_get("/api/v1/sessions")
        session_list = sessions.get("data", sessions) if isinstance(sessions, dict) else sessions
        pending = []
        if isinstance(session_list, list):
            for s in session_list:
                state = s.get("state") or {}
                actions = state.get("required_actions") or []
                if actions:
                    pending.append({
                        "session_id": s.get("id"),
                        "title": s.get("title"),
                        "required_actions": actions,
                    })
        return {"count": len(pending), "approvals": pending}
    except RuntimeError:
        return {"count": 0, "approvals": [], "warning": "TrueForge unavailable"}

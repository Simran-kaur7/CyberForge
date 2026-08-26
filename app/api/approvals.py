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
    message: str = "Investigate and contain the incident"
    thread_id: Optional[str] = None


class DecisionRequest(BaseModel):
    session_id: str
    action_id: str
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
        from app.sdk_client import request_approval
        result = request_approval(
            body.session_id, "block_ip",
            {"incident_id": body.session_id, "message": body.message}
        )
        if not result.get("success"):
            raise HTTPException(status_code=409, detail=result.get("error", "Request failed"))

        # Optionally forward to TrueForge
        tf_event = None
        try:
            tf_event = _tf_post_sse(
                f"/api/v1/sessions/{body.session_id}/turns",
                {"input": [{"type": "user.message", "content": body.message}]},
            )
        except RuntimeError:
            pass  # TrueForge unavailable, local state is sufficient

        return {
            "success": True,
            "action_id": result["action_id"],
            "session_id": body.session_id,
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
        from app.sdk_client import approve_action
        result = approve_action(body.session_id, body.action_id, analyst)
        if not result.get("success"):
            raise HTTPException(status_code=409, detail=result.get("error", "Approval failed"))

        # Optionally forward to TrueForge
        tf_event = None
        try:
            approval_input = {
                "type": "user.tool_approval",
                "tool_call_id": body.action_id,
                "approval": {"status": "allow"},
            }
            if body.thread_id:
                approval_input["thread_id"] = body.thread_id
            tf_event = _tf_post_sse(
                f"/api/v1/sessions/{body.session_id}/turns",
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
        from app.sdk_client import reject_action
        result = reject_action(body.session_id, body.action_id, analyst)
        if not result.get("success"):
            raise HTTPException(status_code=409, detail=result.get("error", "Rejection failed"))

        # Optionally forward to TrueForge
        tf_event = None
        try:
            reason = body.reason or f"Rejected by {analyst}"
            approval_input = {
                "type": "user.tool_approval",
                "tool_call_id": body.action_id,
                "approval": {"status": "deny", "reason": reason},
            }
            if body.thread_id:
                approval_input["thread_id"] = body.thread_id
            tf_event = _tf_post_sse(
                f"/api/v1/sessions/{body.session_id}/turns",
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

"""
CyberForge Approval API — TrueForge native approval gate.

TrueForge create-turn returns an SSE stream. This module:
1. Sends turns (message or approval) via SSE-aware transport
2. Reads events until turn.done or tool.approval_required
3. Returns the terminal event as the response
Requires CYBERFORGE_API_KEY for containment decisions.
"""

import logging
import os
import json
import urllib.request

logger = logging.getLogger(__name__)

try:
    from fastapi import APIRouter, HTTPException, Header
    from fastapi.responses import JSONResponse
except ImportError:  # pragma: no cover - keeps local tests working without FastAPI
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def Header(default=None):
        return default

    class JSONResponse(dict):
        def __init__(self, content=None, status_code: int = 200):
            super().__init__(content or {})
            self.content = content or {}
            self.status_code = status_code

    class APIRouter:
        def __init__(self, *args, **kwargs):
            self.routes = []

        def _decorator(self, *args, **kwargs):
            def wrapper(func):
                self.routes.append((args, kwargs, func))
                return func
            return wrapper

        post = get = delete = _decorator

try:
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - lightweight fallback for tests
    class BaseModel:
        def __init__(self, **data):
            for key, value in data.items():
                setattr(self, key, value)

        def model_dump(self):
            return dict(self.__dict__)

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


class UncertainForwardingResolutionRequest(BaseModel):
    session_id: str
    action_id: str
    confirmed_delivered: bool


def _require_api_key(authorization: Optional[str] = Header(None)) -> str:
    if not EXPECTED_API_KEY:
        import logging
        logging.warning(
            "CYBERFORGE_API_KEY is not set — containment endpoints "
            "are running without authentication.  This is only "
            "safe for local development."
        )
        return "analyst-local-dev"

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
        )

    # Strict Bearer-token parsing: must be exactly "Bearer <token>"
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format; expected 'Bearer <token>'",
        )

    token = parts[1].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Empty Bearer token",
        )

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
        # Covers most network failures, including socket timeouts, since
        # urllib wraps them here in most cases.
        raise RuntimeError("Cannot reach TrueForge") from exc
    except (TimeoutError, OSError) as exc:
        # Belt-and-suspenders: some timeout/connection failures (e.g. a bare
        # socket.timeout/TimeoutError, ConnectionResetError) are not always
        # wrapped in urllib.error.URLError depending on where they occur, so
        # catch the broader OSError family explicitly and normalize it too.
        raise RuntimeError("TrueForge request failed (network error)") from exc


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

    except json.JSONDecodeError as exc:
        raise RuntimeError("TrueForge returned invalid JSON") from exc

    except urllib.error.HTTPError as exc:
        raise RuntimeError("TrueForge returned an error") from exc

    except urllib.error.URLError as exc:
        raise RuntimeError("Cannot reach TrueForge") from exc

    except (TimeoutError, OSError) as exc:
        raise RuntimeError("TrueForge request failed (network error)") from exc


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
            _release_forwarding_claim_locked,
            complete_forwarding,
            retry_approval_forwarding,
            release_request_claim,
            mark_forwarding_dispatched,
            mark_forwarding_uncertain,
            _mark_forwarding_uncertain_locked,
            forwarding_action_lock,
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

                # A successful TrueForge turn may complete without requesting
                # tool approval. Release the forwarding claim so the local
                # approval is not stranded as permanently in-flight.
                #
                # This must NOT be a plain 200 — a 200 tells the frontend's
                # response.ok check that the request succeeded, so it would
                # proceed to bind and decide an action_id with no tool_call_id
                # behind it. Returning 409 here makes response.ok false and
                # routes the client into its retry/error handling instead.
                if not tool_call_id:
                    release_request_claim(
                        local_session_id,
                        action_id,
                    )
                    return JSONResponse(
                        status_code=409,
                        content={
                            "success": False,
                            "action_id": action_id,
                            "session_id": local_session_id,
                            "trueforge_session_id": tf_session_id,
                            "tool_call_id": None,
                            "thread_id": thread_id,
                            "analyst": analyst,
                            "trueforge_event": tf_event,
                            "error": (
                                "TrueForge completed without requesting "
                                "tool approval"
                            ),
                            "retryable": True,
                        },
                    )

            except Exception:
                # Release request claim upon failure so concurrent retries can run.
                # Broadened beyond RuntimeError: TimeoutError, OSError, and any
                # other unexpected failure during forwarding must not leave the
                # request claim stuck, since that would strand the local action.
                release_request_claim(local_session_id, action_id)

                # Keep detailed exception context (including traceback) in
                # server logs only; the client only sees a generic message.
                logger.exception(
                    "TrueForge forward failed for session=%s action=%s",
                    local_session_id,
                    action_id,
                )

                # Return success=false so the client knows the request was NOT
                # forwarded, while keeping the local pending action retryable.
                return {
                    "success": False,
                    "action_id": action_id,
                    "session_id": local_session_id,
                    "trueforge_session_id": tf_session_id,
                    "tool_call_id": None,
                    "thread_id": None,
                    "analyst": analyst,
                    "trueforge_event": None,
                    "error": "Failed to forward request to TrueForge; please retry.",
                    "retryable": True,
                }

        late_forward = None
        forwarding_owner_token = None

        if tool_call_id:
            # Check if the action is already terminal (approved/rejected)
            # — this is a retry of a previous late-forward failure.
            session_data = get_session(local_session_id)
            existing_action = None
            if session_data:
                for a in session_data.get("actions", []):
                    if a.get("action_id") == action_id:
                        existing_action = a
                        break

            is_retry = (
                existing_action is not None
                and existing_action.get("status") in ("approved", "rejected")
                and existing_action.get("tool_call_id") == tool_call_id
                and not existing_action.get("forwarded_to_trueforge")
            )

            if is_retry:
                # Retry the original terminal action's forwarding.
                retry_result = retry_approval_forwarding(
                    local_session_id, action_id, tool_call_id,
                )
                if retry_result.get("success"):
                    if retry_result.get("already_forwarding"):
                        return {
                            "success": True,
                            "action_id": action_id,
                            "session_id": local_session_id,
                            "trueforge_session_id": tf_session_id,
                            "tool_call_id": tool_call_id,
                            "already_forwarding": True,
                        }
                    late_forward = retry_result
                    forwarding_owner_token = retry_result.get("forwarding_owner")
                elif retry_result.get("error"):
                    # Forwarding already complete or action not retryable.
                    raise HTTPException(
                        status_code=409,
                        detail=retry_result["error"],
                    )
            else:
                # Normal path: bind tool_call_id and enter late-forward.
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

                if cas_result.get("already_forwarding"):
                    return {
                        "success": True,
                        "action_id": action_id,
                        "session_id": local_session_id,
                        "trueforge_session_id": tf_session_id,
                        "tool_call_id": tool_call_id,
                        "already_forwarding": True,
                    }

                if cas_result.get("pending_decision"):
                    late_forward = cas_result
                    forwarding_owner_token = cas_result.get("forwarding_owner")

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

            with forwarding_action_lock(local_session_id, action_id):
                # Durably record that a dispatch is about to be attempted
                # *before* making the network call. This is what lets a
                # restart after a crash tell "the POST may have gone out" apart
                # from "the POST was never attempted" — see
                # mark_forwarding_dispatched() for why this ordering matters.
                dispatch_marked = mark_forwarding_dispatched(
                    local_session_id, action_id, owner_token=forwarding_owner_token,
                )
                if not dispatch_marked.get("success"):
                    # Another caller already reclaimed this lease — we no
                    # longer own the claim, so we must not dispatch under it.
                    raise HTTPException(
                        status_code=409,
                        detail=dispatch_marked.get(
                            "error", "Forwarding claim was lost before dispatch",
                        ),
                    )

                try:
                    tf_event = _tf_post_sse(
                        f"/api/v1/sessions/{tf_session_id}/turns",
                        {"input": [approval_input]},
                    )

                    event_type = tf_event.get("type") if isinstance(tf_event, dict) else None
                    if event_type in ("turn.failed", "error"):
                        # TrueForge explicitly reported that the turn failed.
                        # This is a definite application-level failure, not an
                        # ambiguous transport outcome, so the action is safely
                        # retryable. The locked primitive avoids recursively
                        # acquiring the already-held per-action fence.
                        release_result = _release_forwarding_claim_locked(
                            local_session_id,
                            action_id,
                            f"TrueForge reported {event_type}",
                            owner_token=forwarding_owner_token,
                        )
                        if not release_result.get("success"):
                            logger.error(
                                "Could not release failed late-forward claim for "
                                "session=%s action=%s: %s",
                                local_session_id,
                                action_id,
                                release_result.get("error", "unknown error"),
                            )
                            raise HTTPException(
                                status_code=409,
                                detail=release_result.get(
                                    "error", "Forwarding claim could not be released"
                                ),
                            )
                        return {
                            "success": False,
                            "action_id": action_id,
                            "session_id": local_session_id,
                            "trueforge_session_id": tf_session_id,
                            "tool_call_id": tool_call_id,
                            "thread_id": thread_id,
                            "analyst": analyst,
                            "trueforge_event": tf_event,
                            "error": "TrueForge reported that the approval delivery failed.",
                            "retryable": True,
                        }

                    # TrueForge accepted the decision — finalize the
                    # forwarding state so a crash-restart cannot re-forward.
                    complete_forwarding(
                        local_session_id, action_id,
                        owner_token=forwarding_owner_token,
                    )

                except HTTPException:
                    raise
                except Exception:
                    # The dispatch marker was durably written immediately before the
                    # POST. From this point onward, a timeout/reset/read failure may
                    # mean TrueForge already accepted the decision. Do NOT release
                    # the forwarding claim or clear forwarding_dispatched_at, or a
                    # normal retry could submit the same decision twice.
                    logger.exception(
                        "Late-forward decision failed after dispatch for session=%s "
                        "action=%s tool_call_id=%s",
                        local_session_id,
                        action_id,
                        tool_call_id,
                    )

                    # We already hold the per-action fence. Use the fence-held
                    # persistence primitive rather than mark_forwarding_uncertain(),
                    # which would recursively acquire the same non-reentrant lock.
                    mark_result = _mark_forwarding_uncertain_locked(
                        local_session_id,
                        action_id,
                        "Late-forward decision outcome is uncertain",
                        owner_token=forwarding_owner_token,
                    )
                    if not mark_result.get("success"):
                        logger.error(
                            "Could not persist uncertain forwarding state for session=%s "
                            "action=%s: %s",
                            local_session_id,
                            action_id,
                            mark_result.get("error", "unknown error"),
                        )

                    return {
                        "success": False,
                        "action_id": action_id,
                        "session_id": local_session_id,
                        "trueforge_session_id": tf_session_id,
                        "tool_call_id": tool_call_id,
                        "thread_id": thread_id,
                        "analyst": analyst,
                        "trueforge_event": tf_event,
                        "error": "Late-forward decision outcome is uncertain; manual verification required.",
                        "uncertain_delivery": True,
                        "retryable": False,
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

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Approval request failed due to an internal error.",
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


def _best_effort_block_ip(session_id: str) -> dict:
    """Execute block_ip locally as a best-effort firewall update.

    Returns a dict with:
      - containment_status: "executed" | "failed" | "target_unresolvable"
      - contained_ip: the IP that was targeted (if any)
      - block_error: error message if block_ip failed (if any)
    """
    try:
        from mcp_server.tools.block_ip import block_ip
        import json as _json, pathlib as _pathlib, re as _re
        from app.sdk_client import get_session as _get

        session = _get(session_id)
        if not session:
            return {"containment_status": "target_unresolvable", "contained_ip": None}

        target_ip = session.get("target_ip")
        # Fallback: extract IP from evidence_snapshot
        if not target_ip or target_ip == "unknown":
            ev = session.get("evidence_snapshot", {})
            if isinstance(ev, dict):
                target_ip = ev.get("source_ip") or ev.get("target_ip")
        # Fallback: extract IP from query text
        if not target_ip or target_ip == "unknown":
            q = session.get("query") or ""
            m = _re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", q)
            if m:
                target_ip = m.group(1)

        if not target_ip or target_ip == "unknown":
            return {"containment_status": "target_unresolvable", "contained_ip": None}

        block_result = block_ip(target_ip)
        if not block_result.get("success"):
            return {
                "containment_status": "failed",
                "contained_ip": target_ip,
                "block_error": block_result.get("error", "block_ip returned success=false"),
            }

        # Record containment in the session so frontend reflects it
        from app.sdk_client import update_session as _upd
        from datetime import datetime as _dt, timezone as _tz
        _upd(
            session_id,
            contained_at=_dt.now(_tz.utc).isoformat(),
            contained_ip=target_ip,
            containment_action="block_ip",
        )
        return {"containment_status": "executed", "contained_ip": target_ip}
    except Exception as exc:
        return {"containment_status": "failed", "contained_ip": None, "block_error": str(exc)}


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
        except Exception:
            # TrueForge forwarding failed — the action must remain
            # pending/retryable. Do NOT call complete_decision or
            # block_ip: the upstream tool call may still be pending
            # and a retry must be possible.
            logger.exception(
                "TrueForge decision forwarding failed for session=%s "
                "action=%s tool_call_id=%s",
                body.session_id,
                body.action_id,
                tool_call_id,
            )
            fail_decision(
                body.session_id,
                body.action_id,
                token,
                "TrueForge decision forwarding failed",
            )
            return {
                "success": False,
                "action_id": body.action_id,
                "session_id": body.session_id,
                "status": "pending",
                "analyst": analyst,
                "trueforge_event": tf_event,
                "error": "TrueForge decision forwarding failed; retryable.",
                "retryable": True,
            }

    completed = complete_decision(
        body.session_id,
        body.action_id,
        token,
    )
    if not completed.get("success"):
        raise HTTPException(status_code=409, detail=completed.get("error", "Decision finalization failed"))

    # Execute block_ip when approved so the firewall file is updated.
    containment = {"containment_status": "not_needed"}
    if decision == "approved":
        containment = _best_effort_block_ip(body.session_id)

    return {
        "success": True,
        "action_id": body.action_id,
        "status": completed["status"],
        "analyst": analyst,
        "trueforge_event": tf_event,
        **containment,
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


@router.post("/resolve-uncertain")
def resolve_uncertain_approval_forwarding(
    body: UncertainForwardingResolutionRequest,
    authorization: Optional[str] = Header(None),
):
    """Resolve a post-dispatch TrueForge delivery outcome after operator verification."""
    resolved_by = _require_api_key(authorization)
    try:
        from app.sdk_client import get_session, resolve_uncertain_forwarding

        session = get_session(body.session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        result = resolve_uncertain_forwarding(
            body.session_id,
            body.action_id,
            body.confirmed_delivered,
            resolved_by=resolved_by,
        )
        if not result.get("success"):
            raise HTTPException(
                status_code=409,
                detail=result.get("error", "Could not resolve uncertain forwarding"),
            )

        return {
            **result,
            "session_id": body.session_id,
            "resolved_by": resolved_by,
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "Uncertain forwarding resolution failed for session=%s action=%s",
            body.session_id,
            body.action_id,
        )
        raise HTTPException(
            status_code=500,
            detail="Uncertain forwarding resolution failed due to an internal error.",
        )


@router.get("/pending")
def get_pending_approvals(
    authorization: Optional[str] = Header(None),
):
    """List pending approval state; this is analyst-only information."""
    _require_api_key(authorization)
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
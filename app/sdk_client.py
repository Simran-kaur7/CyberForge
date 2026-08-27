"""
CyberForge SDK Client — Tool Runner, Session & Approval Management

1. Tool execution with timeout and error handling
2. Session management: create, get, list, find by incident ID
3. Approval flow: request -> pending -> approve/reject (enforced)
4. Local JSON persistence with file locking
"""

import os
import platform
import sys

if platform.system() == "Windows":
    import msvcrt
    def _lock_file(fd):
        msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
    def _unlock_file(fd):
        msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl
    def _lock_file(fd):
        fcntl.flock(fd, fcntl.LOCK_EX)
    def _unlock_file(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "mcp_server" / "tools"
DATA_DIR = PROJECT_ROOT / "mcp_server" / "data"
SESSIONS_FILE = DATA_DIR / "sessions.json"

TOOL_TIMEOUT_SECONDS = 15
MAX_ERROR_OUTPUT = 500


class ToolTimeoutError(RuntimeError):
    """Raised when an investigation tool exceeds its execution timeout."""


# ---------------------------------------------------------------------------
# Tool Execution
# ---------------------------------------------------------------------------

def run_tool(script_name: str, *args: str) -> dict:
    """Run an MCP Python tool and return parsed JSON output."""
    script_path = TOOLS_DIR / script_name
    try:
        result = subprocess.run(
            [sys.executable, str(script_path), *args],
            cwd=TOOLS_DIR,
            capture_output=True,
            text=True,
            check=False,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "").strip()
        stderr = (exc.stderr or "").strip()
        details = []
        if args:
            details.append(f"args={args}")
        if stdout:
            details.append(f"stdout={stdout[-MAX_ERROR_OUTPUT:]}")
        if stderr:
            details.append(f"stderr={stderr[-MAX_ERROR_OUTPUT:]}")
        context = "; ".join(details)
        raise ToolTimeoutError(
            f"{script_name} timed out after "
            f"{TOOL_TIMEOUT_SECONDS} seconds"
            + (f" ({context})" if context else "")
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{script_name} returned invalid JSON") from exc


def analyze_evidence() -> dict:
    return run_tool("analyze_evidence.py")


def search_security_logs(query: str = "") -> dict:
    return run_tool("search_security_logs.py", query)


def check_system_activity() -> dict:
    return run_tool("check_system_activity.py")


def block_ip(ip_address: str) -> dict:
    return run_tool("block_ip.py", ip_address)


# ---------------------------------------------------------------------------
# Session Persistence (with file locking)
# ---------------------------------------------------------------------------

def _load_sessions() -> list:
    if not SESSIONS_FILE.exists():
        return []
    try:
        return json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        # Corrupted sessions file — back it up and start fresh
        import shutil
        backup = SESSIONS_FILE.with_suffix(".json.corrupted")
        try:
            shutil.copy2(SESSIONS_FILE, backup)
        except OSError:
            pass
        return []


def _save_sessions(sessions: list) -> None:
    """Atomically write sessions: write to a temp file, then rename."""
    import tempfile
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(DATA_DIR), suffix=".tmp", prefix="sessions_"
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(sessions, indent=2, default=str))
            f.flush()
            os.fsync(f.fileno())
        # Atomic replace (on same filesystem)
        os.replace(tmp_path, str(SESSIONS_FILE))
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _mutate_sessions(fn):
    """Load, apply fn, save — under an exclusive file lock."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = DATA_DIR / ".sessions.lock"
    lock_path.touch(exist_ok=True)
    fd = open(lock_path, "r+")
    try:
        _lock_file(fd)
        sessions = _load_sessions()
        result = fn(sessions)
        _save_sessions(sessions)
        return result
    finally:
        try:
            _unlock_file(fd)
        finally:
            fd.close()


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

def create_session(
    incident_id: str,
    evidence_snapshot=None,
    risk_score=None,
    **metadata,
) -> dict:
    """Create a session, populated with all investigation state up front.

    ``risk_score`` and any extra ``metadata`` (e.g. ``target_ip``, ``query``)
    are written in the same locked mutation as the session itself, so a
    caller never has to follow up with a second write to make the session
    complete — an incomplete session can therefore never escape.
    """
    def _create(sessions):
        sid = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        s = {
            "id": sid, "incident_id": incident_id, "status": "active",
            "created_at": now, "updated_at": now,
            "evidence_snapshot": evidence_snapshot or {},
            "risk_score": risk_score, "approval_state": None,
            "trueforge_session_id": None,
            "actions": [], "findings": [],
        }
        # Extra metadata may only add fields, never redefine core state.
        for key, value in metadata.items():
            if key not in s:
                s[key] = value
        sessions.append(s)
        return s
    return _mutate_sessions(_create)


def _read_sessions() -> list:
    """Read sessions under the file lock for a consistent snapshot."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = DATA_DIR / ".sessions.lock"
    lock_path.touch(exist_ok=True)
    fd = open(lock_path, "r+")
    try:
        _lock_file(fd)
        return _load_sessions()
    finally:
        try:
            _unlock_file(fd)
        finally:
            fd.close()


def get_session(sid: str):
    for s in _read_sessions():
        if s["id"] == sid:
            return s
    return None


def list_sessions() -> list:
    return [
        {
            "id": s["id"], "incident_id": s["incident_id"],
            "status": s["status"], "created_at": s["created_at"],
            "risk_score": s.get("risk_score"),
            "approval_state": s.get("approval_state"),
            "trueforge_session_id": s.get("trueforge_session_id"),
        }
        for s in _read_sessions()
    ]


def find_session_by_incident(iid: str, target_ip: str | None = None):
    """Return the newest session for an incident id, or None.

    An empty/None id never matches: session reuse must be driven by a real
    incident identifier, otherwise unrelated investigations would collapse
    onto whichever session happens to lack one.

    When ``target_ip`` is supplied, only sessions recorded against that exact
    target match. Reuse must never join investigations of different targets —
    they carry independent evidence, risk and approval state.
    """
    if not iid or not isinstance(iid, str):
        return None
    matches = []
    for s in _read_sessions():
        if not isinstance(s, dict) or s.get("incident_id") != iid:
            continue
        if target_ip is not None and (s.get("target_ip") or "") != target_ip:
            continue
        matches.append(s)
    if not matches:
        return None
    return sorted(
        matches, key=lambda s: s.get("created_at") or "", reverse=True
    )[0]


# ---------------------------------------------------------------------------
# Approval Flow (enforced state machine)
# ---------------------------------------------------------------------------

def request_approval(sid: str, atype: str, adetail: dict) -> dict:
    """Request approval, reusing an existing compatible pending approval and claiming forward atomically."""
    def _req(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue

            existing = s.get("approval_state")

            if existing and existing.get("status") == "pending":
                existing_detail = existing.get("action_detail") or {}

                if (
                    existing_detail.get("incident_id")
                    == adetail.get("incident_id")
                    and not existing.get("tool_call_id")
                ):
                    # Check if another concurrent request is actively forwarding to TrueForge
                    if existing.get("request_in_flight"):
                        return {
                            "success": False,
                            "error": "A request to TrueForge is already in flight for this approval action",
                            "in_flight": True,
                        }

                    # Atomically claim the request forward
                    existing["request_in_flight"] = True
                    for action in s.get("actions", []):
                        if action.get("action_id") == existing["action_id"]:
                            action["request_in_flight"] = True
                            break

                    s["updated_at"] = datetime.now(timezone.utc).isoformat()

                    return {
                        "success": True,
                        "action_id": existing["action_id"],
                        "status": "pending",
                        "reused": True,
                    }

                return {
                    "success": False,
                    "error": "An approval is already pending for this session",
                }

            aid = str(uuid.uuid4())[:8]
            now = datetime.now(timezone.utc).isoformat()

            ap = {
                "action_id": aid,
                "action_type": atype,
                "action_detail": adetail,
                "status": "pending",
                "requested_at": now,
                "decided_at": None,
                "decided_by": None,
                "request_in_flight": True,  # Claim initial forward
            }

            s["approval_state"] = ap
            s["actions"].append(ap)
            s["updated_at"] = now

            return {
                "success": True,
                "action_id": aid,
                "status": "pending",
                "reused": False,
            }

        return {
            "success": False,
            "error": "Session not found",
        }

    return _mutate_sessions(_req)


def release_request_claim(sid: str, action_id: str) -> dict:
    """Release the in-flight claim on a request forward if TrueForge call fails."""
    def _release(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue

            ap = s.get("approval_state")
            if ap and ap.get("action_id") == action_id:
                ap["request_in_flight"] = False

            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    action["request_in_flight"] = False
                    break

            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "action_id": action_id}

        return {"success": False, "error": "Session not found"}

    return _mutate_sessions(_release)


def _validate_decision_ids(
    session: dict,
    current: dict,
    expected_tool_call_id: str | None,
    expected_trueforge_session_id: str | None,
) -> tuple[bool, str | None]:
    stored_tool_call_id = current.get("tool_call_id")
    stored_tf_session_id = session.get("trueforge_session_id")

    if expected_tool_call_id and stored_tool_call_id:
        if expected_tool_call_id != stored_tool_call_id:
            return False, "tool_call_id does not belong to this action"
    elif expected_tool_call_id and not stored_tool_call_id:
        return False, "No authoritative tool_call_id is stored for this action"

    if expected_trueforge_session_id and stored_tf_session_id:
        if expected_trueforge_session_id != stored_tf_session_id:
            return False, "trueforge_session_id does not belong to this action"
    elif expected_trueforge_session_id and not stored_tf_session_id:
        return False, "No authoritative trueforge_session_id is stored for this action"

    return True, None


def prepare_decision(
    sid: str,
    aid: str,
    decision: str,
    decided_by: str = "analyst",
    expected_tool_call_id: str | None = None,
    expected_trueforge_session_id: str | None = None,
) -> dict:
    """Atomically reserve a pending decision before forwarding it upstream.

    The local action remains pending until the TrueForge decision is successfully
    delivered. This makes upstream failures retryable and prevents two concurrent
    requests from making opposite decisions for the same action.
    """
    if decision not in ("approved", "rejected"):
        return {"success": False, "error": "Invalid decision"}

    def _prepare(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue

            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "No matching pending approval"}

            if current.get("status") != "pending":
                return {
                    "success": False,
                    "error": f"Action already {current.get('status')}",
                }

            valid, error = _validate_decision_ids(
                s,
                current,
                expected_tool_call_id,
                expected_trueforge_session_id,
            )
            if not valid:
                return {"success": False, "error": error}

            reservation = current.get("decision_in_progress")

            if reservation:
                original_decision = reservation.get("decision")

                # FIX FOR ISSUE #2: A reclaimed reservation MUST NOT change the original decision
                if decision != original_decision:
                    return {
                        "success": False,
                        "error": (
                            f"A decision forward for '{original_decision}' is already in progress or abandoned; "
                            f"cannot change decision to '{decision}'"
                        ),
                    }

                started_at = reservation.get("started_at")
                stale = False

                if started_at:
                    try:
                        started = datetime.fromisoformat(
                            started_at.replace("Z", "+00:00")
                        )
                        age_seconds = (
                            datetime.now(timezone.utc) - started
                        ).total_seconds()

                        # A forwarding reservation older than 5 minutes
                        # is considered abandoned and can be safely reclaimed.
                        stale = age_seconds > 300

                    except (TypeError, ValueError):
                        # Invalid reservation timestamps are treated as stale
                        # so corrupted state cannot permanently block decisions.
                        stale = True
                else:
                    stale = True

                if not stale:
                    return {
                        "success": False,
                        "error": "A decision is already being forwarded",
                    }

                # Reclaim an abandoned reservation preserving original decision
                current.pop("decision_in_progress", None)

                for action in s.get("actions", []):
                    if action.get("action_id") == aid:
                        action.pop("decision_in_progress", None)
                        break

            token = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()
            current["decision_in_progress"] = {
                "token": token,
                "decision": decision,
                "decided_by": decided_by,
                "started_at": now,
            }

            for action in s.get("actions", []):
                if action.get("action_id") == aid:
                    action["decision_in_progress"] = dict(
                        current["decision_in_progress"]
                    )
                    break

            s["updated_at"] = now
            return {
                "success": True,
                "action_id": aid,
                "decision": decision,
                "token": token,
                "tool_call_id": current.get("tool_call_id"),
                "trueforge_session_id": s.get("trueforge_session_id"),
                "thread_id": current.get("thread_id"),
            }

        return {"success": False, "error": "Session not found"}

    return _mutate_sessions(_prepare)


def complete_decision(sid: str, aid: str, token: str) -> dict:
    """Finalize a decision after TrueForge accepted the forwarded request."""
    def _complete(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue

            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "Action not found"}

            reservation = current.get("decision_in_progress")
            if not reservation or reservation.get("token") != token:
                return {"success": False, "error": "Decision reservation is no longer valid"}

            decision = reservation["decision"]
            now = datetime.now(timezone.utc).isoformat()
            current["status"] = decision
            current["decided_at"] = now
            current["decided_by"] = reservation.get("decided_by", "analyst")
            current.pop("decision_in_progress", None)
            current.pop("forward_error", None)

            for action in s.get("actions", []):
                if action.get("action_id") == aid:
                    action["status"] = decision
                    action["decided_at"] = now
                    action["decided_by"] = reservation.get("decided_by", "analyst")
                    action.pop("decision_in_progress", None)
                    action.pop("forward_error", None)
                    break

            s["updated_at"] = now
            return {
                "success": True,
                "action_id": aid,
                "status": decision,
                "tool_call_id": current.get("tool_call_id"),
                "trueforge_session_id": s.get("trueforge_session_id"),
            }

        return {"success": False, "error": "Session not found"}

    return _mutate_sessions(_complete)


def fail_decision(sid: str, aid: str, token: str, error: str) -> dict:
    """Release a failed upstream decision while keeping the local action pending."""
    def _fail(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue

            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "Action not found"}

            reservation = current.get("decision_in_progress")
            if not reservation or reservation.get("token") != token:
                return {"success": False, "error": "Decision reservation is no longer valid"}

            current.pop("decision_in_progress", None)
            current["forward_error"] = error
            now = datetime.now(timezone.utc).isoformat()

            for action in s.get("actions", []):
                if action.get("action_id") == aid:
                    action.pop("decision_in_progress", None)
                    action["forward_error"] = error
                    break

            s["updated_at"] = now
            return {
                "success": True,
                "action_id": aid,
                "status": current.get("status", "pending"),
                "retryable": True,
            }

        return {"success": False, "error": "Session not found"}

    return _mutate_sessions(_fail)


def approve_action(
    sid: str,
    aid: str,
    decided_by: str = "analyst",
    expected_tool_call_id: str | None = None,
    expected_trueforge_session_id: str | None = None,
) -> dict:
    """Legacy local-only approval helper; use prepare/complete for upstream forwarding."""
    def _approve(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "No matching pending approval"}
            if current.get("status") != "pending":
                return {"success": False, "error": f"Action already {current.get('status')}"}
            valid, error = _validate_decision_ids(
                s, current, expected_tool_call_id, expected_trueforge_session_id
            )
            if not valid:
                return {"success": False, "error": error}
            now = datetime.now(timezone.utc).isoformat()
            current["status"] = "approved"
            current["decided_at"] = now
            current["decided_by"] = decided_by
            for action in s.get("actions", []):
                if action.get("action_id") == aid:
                    action.update(
                        status="approved",
                        decided_at=now,
                        decided_by=decided_by,
                    )
                    break
            s["updated_at"] = now
            return {
                "success": True,
                "action_id": aid,
                "status": "approved",
                "tool_call_id": current.get("tool_call_id"),
                "trueforge_session_id": s.get("trueforge_session_id"),
            }
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_approve)


def reject_action(
    sid: str,
    aid: str,
    decided_by: str = "analyst",
    expected_tool_call_id: str | None = None,
    expected_trueforge_session_id: str | None = None,
) -> dict:
    """Legacy local-only rejection helper; use prepare/complete for upstream forwarding."""
    def _reject(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "No matching pending approval"}
            if current.get("status") != "pending":
                return {"success": False, "error": f"Action already {current.get('status')}"}
            valid, error = _validate_decision_ids(
                s, current, expected_tool_call_id, expected_trueforge_session_id
            )
            if not valid:
                return {"success": False, "error": error}
            now = datetime.now(timezone.utc).isoformat()
            current["status"] = "rejected"
            current["decided_at"] = now
            current["decided_by"] = decided_by
            for action in s.get("actions", []):
                if action.get("action_id") == aid:
                    action.update(
                        status="rejected",
                        decided_at=now,
                        decided_by=decided_by,
                    )
                    break
            s["updated_at"] = now
            return {
                "success": True,
                "action_id": aid,
                "status": "rejected",
                "tool_call_id": current.get("tool_call_id"),
                "trueforge_session_id": s.get("trueforge_session_id"),
            }
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_reject)

#: Fields that define a session's identity and approval lifecycle. These are
#: managed by the dedicated helpers above and must never be silently
#: overwritten by a bulk metadata update.
_PROTECTED_SESSION_KEYS = frozenset({
    "id", "incident_id", "created_at",
    "actions", "approval_state", "trueforge_session_id",
})

_REINVESTIGATION_SUPERSEDE_REASON = (
    "Superseded: the investigation was re-run, so this approval was requested "
    "against evidence/risk that has since been replaced."
)


def _supersede_pending_approval(session: dict) -> str | None:
    """Retire a still-pending approval on ``session`` in place.

    Must be called while holding the sessions lock (i.e. from inside a
    ``_mutate_sessions`` callback) so the transition is atomic with whatever
    else the mutation changes.

    A pending approval is bound to a TrueForge ``tool_call_id`` from the
    investigation run that requested it. Once that run's evidence, risk, target
    or query is replaced by a re-investigation, deciding the approval would
    authorize a tool call against state the analyst never reviewed — so it must
    stop being decidable. Marking it terminal here means ``prepare_decision``
    and the legacy approve/reject helpers all reject it, while a fresh approval
    can still be requested against the new evidence.

    Returns the retired action id, or ``None`` when there was nothing pending.
    """
    current = session.get("approval_state")
    if not isinstance(current, dict) or current.get("status") != "pending":
        return None

    action_id = current.get("action_id")
    now = datetime.now(timezone.utc).isoformat()

    def _retire(record: dict) -> None:
        record["status"] = "superseded"
        record["decided_at"] = now
        record["decided_by"] = "system:reinvestigation"
        record["superseded_reason"] = _REINVESTIGATION_SUPERSEDE_REASON
        # Drop any transient claim so nothing downstream treats the retired
        # approval as live, in-flight, or mid-decision.
        record.pop("decision_in_progress", None)
        record["request_in_flight"] = False

    _retire(current)
    for action in session.get("actions", []):
        if isinstance(action, dict) and action.get("action_id") == action_id:
            _retire(action)
            break

    return action_id


def update_session(sid: str, *, supersede_stale_approval: bool = False, **kw) -> dict:
    """Merge investigation state into an existing session.

    Returns ``{"success": False, ...}`` when the session is missing or when
    the caller attempts to overwrite identity/approval fields. Callers must
    treat a failed update as a hard error: a session that did not persist
    cannot be used to authorize containment.

    When ``supersede_stale_approval`` is set, any approval that is still pending
    is retired in the *same* locked mutation as the field merge. Reusing an
    incident's session for a new investigation run replaces the evidence and
    risk an analyst reasons about; a pending approval left behind was requested
    against the superseded state and is bound to that run's TrueForge tool call,
    so it must not remain decidable. Doing both in one mutation closes the
    window in which a concurrent decision could authorize the stale call after
    the evidence has already changed. The retired action id, when any, is
    returned as ``superseded_action_id``.
    """
    if not sid or not isinstance(sid, str):
        return {"success": False, "error": "Session id is required"}
    if not kw:
        return {"success": False, "error": "No fields to update"}

    protected = sorted(k for k in kw if k in _PROTECTED_SESSION_KEYS)
    if protected:
        return {
            "success": False,
            "error": (
                "Cannot update protected session fields: "
                + ", ".join(protected)
            ),
        }

    def _update(sessions):
        for s in sessions:
            if isinstance(s, dict) and s.get("id") == sid:
                s.update(kw)
                superseded_action_id = (
                    _supersede_pending_approval(s)
                    if supersede_stale_approval
                    else None
                )
                s["updated_at"] = datetime.now(timezone.utc).isoformat()
                result = {"success": True, "session": s}
                if superseded_action_id:
                    result["superseded_action_id"] = superseded_action_id
                return result
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_update)


def set_approval_tool_call_id(
    sid: str,
    action_id: str,
    tool_call_id: str,
    thread_id: str | None = None,
) -> dict:
    """Atomically bind the TrueForge call/thread to a local approval action and clear request claim."""
    def _set(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue

            target = None
            ap = s.get("approval_state")
            if ap and ap.get("action_id") == action_id:
                target = ap

            if target is None:
                for action in s.get("actions", []):
                    if action.get("action_id") == action_id:
                        target = action
                        break

            if target is None:
                return {"success": False, "error": "Action not found"}

            target["tool_call_id"] = tool_call_id
            target["request_in_flight"] = False  # Unset claim upon binding
            if thread_id:
                target["thread_id"] = thread_id

            if ap and ap.get("action_id") == action_id and target is not ap:
                ap["tool_call_id"] = tool_call_id
                ap["request_in_flight"] = False
                if thread_id:
                    ap["thread_id"] = thread_id

            for action in s.get("actions", []):
                if action.get("action_id") == action_id and action is not target:
                    action["tool_call_id"] = tool_call_id
                    action["request_in_flight"] = False
                    if thread_id:
                        action["thread_id"] = thread_id
                    target = action if target is None else target

            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            current_status = target.get("status")

            if current_status in ("approved", "rejected"):
                for action in s.get("actions", []):
                    if action.get("action_id") == action_id:
                        if not action.get("forwarded_to_trueforge"):
                            action["forwarded_to_trueforge"] = True
                            return {
                                "success": True,
                                "action_id": action_id,
                                "pending_decision": current_status,
                                "decided_by": action.get("decided_by"),
                            }
                        return {
                            "success": True,
                            "action_id": action_id,
                            "already_forwarded": True,
                        }

            return {"success": True, "action_id": action_id}

        return {"success": False, "error": "Session not found"}

    return _mutate_sessions(_set)


def release_forwarding_claim(sid: str, action_id: str, error: str) -> dict:
    """Release a late-forward claim after an upstream delivery failure."""
    def _release(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    action["forwarded_to_trueforge"] = False
                    action["forward_error"] = error
                    s["updated_at"] = datetime.now(timezone.utc).isoformat()
                    return {"success": True, "action_id": action_id, "retryable": True}
            return {"success": False, "error": "Action not found"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_release)

def persist_trueforge_session_id(sid: str, tf_session_id: str) -> dict:
    """Atomically persist a TrueForge session ID on the local session."""
    def _persist(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            existing = s.get("trueforge_session_id")
            if existing:
                return {"success": True, "trueforge_session_id": existing, "reused": True}
            s["trueforge_session_id"] = tf_session_id
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "trueforge_session_id": tf_session_id, "reused": False}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_persist)


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        print(json.dumps(list_sessions(), indent=2))
    elif cmd == "tools":
        print(json.dumps(analyze_evidence(), indent=2))
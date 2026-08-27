"""
CyberForge SDK Client — Tool Runner, Session & Approval Management

1. Tool execution with timeout and error handling
2. Session management: create, get, list, find by incident ID
3. Approval flow: request -> pending -> approve/reject (enforced)
4. Local JSON persistence with file locking
"""

import hashlib
import os
import platform
import sys
from contextlib import contextmanager

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
# Lease timeout for request_in_flight claims.  If a TrueForge request
# does not return within this window the claim is considered abandoned
# and may be reclaimed atomically.
REQUEST_CLAIM_TIMEOUT_SECONDS = 300  # 5 minutes
# Lease timeout for forwarding_to_trueforge claims.  A crashed owner's
# forwarding claim must not block retries indefinitely.
FORWARDING_CLAIM_TIMEOUT_SECONDS = 300  # 5 minutes

# Number of shared forwarding-lock fence files. sid+action_id pairs are
# hashed into this fixed-size pool instead of getting a unique file each,
# so lock-file count stays bounded no matter how many approval actions
# have ever been created (action_id is a fresh uuid4 every time, so a
# 1:1 mapping would grow forever). Deleting a lock file after use isn't
# safe here since retry_approval_forwarding can re-enter the same
# action_id's fence later, and unlinking risks the classic unlink-race
# where a waiter still holds the old inode.
FORWARDING_LOCK_BUCKETS = 256

# Tracks how many threads currently hold DATA_DIR/.sessions.lock.
# Used to prove TrueForge network I/O never runs under the global lock.
_sessions_lock_depth = 0


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


def sessions_lock_held() -> bool:
    """Return True if this process currently holds .sessions.lock."""
    return _sessions_lock_depth > 0


def _mutate_sessions(fn):
    """Load, apply fn, save — under an exclusive file lock."""
    global _sessions_lock_depth
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = DATA_DIR / ".sessions.lock"
    lock_path.touch(exist_ok=True)
    fd = open(lock_path, "r+")
    try:
        _lock_file(fd)
        _sessions_lock_depth += 1
        sessions = _load_sessions()
        result = fn(sessions)
        _save_sessions(sessions)
        return result
    finally:
        try:
            if _sessions_lock_depth:
                _sessions_lock_depth -= 1
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
    global _sessions_lock_depth
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = DATA_DIR / ".sessions.lock"
    lock_path.touch(exist_ok=True)
    fd = open(lock_path, "r+")
    try:
        _lock_file(fd)
        _sessions_lock_depth += 1
        return _load_sessions()
    finally:
        try:
            if _sessions_lock_depth:
                _sessions_lock_depth -= 1
            _unlock_file(fd)
        finally:
            fd.close()


def forwarding_lock_path(sid: str, action_id: str) -> Path:
    """Shared lock-file identity for one CyberForge approval action's TrueForge forward.

    Maps (sid, action_id) onto a fixed-size pool of fence files via a stable
    hash, rather than minting a unique file per action. The file's contents
    are never read — it exists only to be flock()'d — so two unrelated
    actions occasionally sharing a bucket just means a brief, harmless
    serialization between their (short, infrequent) forwarding operations.
    This keeps forwarding_locks/ bounded at FORWARDING_LOCK_BUCKETS files
    regardless of how many approval actions the process has ever handled.
    """
    lock_dir = DATA_DIR / "forwarding_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(f"{sid}_{action_id}".encode("utf-8")).hexdigest()
    bucket = int(digest, 16) % FORWARDING_LOCK_BUCKETS
    return lock_dir / f"bucket_{bucket:04d}.lock"


@contextmanager
def forwarding_action_lock(sid: str, action_id: str):
    """Exclusive per-action fence. Must not be held around unrelated sessions I/O.

    Claim, reclaim, TrueForge dispatch, complete, and release for the same
    ``session_id`` + ``action_id`` all serialize on this lock. The global
    ``.sessions.lock`` is acquired only for short durable reads/writes inside.
    """
    path = forwarding_lock_path(sid, action_id)
    path.touch(exist_ok=True)
    fd = open(path, "r+")
    try:
        _lock_file(fd)
        yield path
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
                    # Check if another concurrent request is actively forwarding to
                    # TrueForge. A stale claim (owner crashed before releasing it)
                    # must not block approval forever — treat an expired lease as
                    # abandoned, same as _has_active_approval_operation() does.
                    if existing.get("request_in_flight"):
                        request_started = existing.get("request_started_at")
                        claim_expired = True
                        if request_started and isinstance(request_started, str):
                            try:
                                started = datetime.fromisoformat(
                                    request_started.replace("Z", "+00:00")
                                )
                                age_seconds = (
                                    datetime.now(timezone.utc) - started
                                ).total_seconds()
                                claim_expired = age_seconds > REQUEST_CLAIM_TIMEOUT_SECONDS
                            except (TypeError, ValueError):
                                claim_expired = True
                        if not claim_expired:
                            return {
                                "success": False,
                                "error": "A request to TrueForge is already in flight for this approval action",
                                "in_flight": True,
                            }
                        # Lease expired — fall through and reclaim the stale claim.

                    # Atomically claim the request forward
                    now_claim = datetime.now(timezone.utc).isoformat()
                    existing["request_in_flight"] = True
                    existing["request_started_at"] = now_claim
                    for action in s.get("actions", []):
                        if action.get("action_id") == existing["action_id"]:
                            action["request_in_flight"] = True
                            action["request_started_at"] = now_claim
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
                "request_started_at": now,   # Lease timestamp
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
                ap.pop("request_started_at", None)

            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    action["request_in_flight"] = False
                    action.pop("request_started_at", None)
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
    """Legacy local-only approval helper; use prepare/complete for upstream forwarding.

    Deciding locally does not wait on the initial ``request_approval`` claim
    (``request_in_flight``) — only a competing decision forward
    (``decision_in_progress``) blocks this. See
    ``_has_competing_decision_operation`` for why.
    """
    def _approve(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "No matching pending approval"}
            if current.get("status") != "pending":
                return {"success": False, "error": f"Action already {current.get('status')}"}
            active_reason = _has_competing_decision_operation(s)
            if active_reason:
                return {"success": False, "error": active_reason}
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
    """Legacy local-only rejection helper; use prepare/complete for upstream forwarding.

    Deciding locally does not wait on the initial ``request_approval`` claim
    (``request_in_flight``) — only a competing decision forward
    (``decision_in_progress``) blocks this. See
    ``_has_competing_decision_operation`` for why.
    """
    def _reject(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "No matching pending approval"}
            if current.get("status") != "pending":
                return {"success": False, "error": f"Action already {current.get('status')}"}
            active_reason = _has_competing_decision_operation(s)
            if active_reason:
                return {"success": False, "error": active_reason}
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


def _is_forwarding_claim_active(action: dict) -> bool:
    """Return True if the action's forwarding claim is still within its lease.

    An expired or missing ``forwarding_started_at`` timestamp means the
    owner process has likely crashed and the claim should be reclaimable.
    """
    if not action.get("forwarding_to_trueforge"):
        return False
    started = action.get("forwarding_started_at")
    if not started or not isinstance(started, str):
        return False
    try:
        start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - start_dt).total_seconds()
        return age <= FORWARDING_CLAIM_TIMEOUT_SECONDS
    except (TypeError, ValueError):
        return False


def _forwarding_needs_manual_resolution(action: dict) -> bool:
    """True when a forwarding claim's lease has expired *and* a dispatch to
    TrueForge was actually attempted under that claim, so the outcome of
    that attempt is unknown.

    ``forwarding_dispatched_at`` is written durably (see
    ``mark_forwarding_dispatched``) immediately before the outbound POST to
    TrueForge — i.e. before the exact window in which a process crash can
    no longer be told apart from "never tried." If that marker is present
    once the lease expires, forwarding_to_trueforge/forwarded_to_trueforge
    alone can't tell us whether the POST landed: TrueForge has no
    idempotency-key contract, so silently reclaiming the lease and
    re-POSTing risks delivering the same decision twice.

    Automatic reclaim (in ``retry_approval_forwarding`` and
    ``set_approval_tool_call_id``) must stop here and surface the
    uncertainty instead of retrying. An operator resolves it explicitly via
    ``resolve_uncertain_forwarding`` after checking TrueForge out-of-band.

    A lease that expired *before* any dispatch was attempted (crash while
    merely holding the claim, e.g. before the network call was even made)
    is unaffected — that case never sets the marker and remains safe to
    reclaim automatically, same as before.
    """
    if not action.get("forwarding_to_trueforge"):
        return False
    if action.get("forwarded_to_trueforge"):
        return False
    if not action.get("forwarding_dispatched_at"):
        return False
    return not _is_forwarding_claim_active(action)


def _has_competing_decision_operation(session: dict) -> str | None:
    """Return a human-readable reason if a *decision* forward is actively
    racing this session's pending approval, or ``None`` if a local
    terminal decision (``approve_action``/``reject_action``) may proceed.

    This is intentionally narrower than ``_has_active_approval_operation``:
    it only looks at ``decision_in_progress`` — the reservation
    ``prepare_decision`` takes while a decision is being forwarded
    upstream, and the one operation a legacy local decision could
    actually race with a conflicting outcome for the same action.

    It deliberately does NOT consider ``request_in_flight``. That flag
    marks the *initial* approval-request notification to TrueForge as
    still claimed/being forwarded — set unconditionally by
    ``request_approval`` whenever it creates a new pending approval (see
    ``request_in_flight: True,  # Claim initial forward`` above). It is
    unrelated to deciding the action locally: ``approve_action`` and
    ``reject_action`` are documented as local-only helpers, and the
    late tool-call binding flow (``set_approval_tool_call_id``) already
    handles attaching a ``tool_call_id`` to an approved/rejected action
    after the fact. Treating ``request_in_flight`` as blocking here would
    make every immediate approve/reject fail, since that claim is present
    on essentially every freshly created pending approval.

    Must be called under the same session lock as the mutation it guards.
    """
    current = session.get("approval_state")
    if not isinstance(current, dict) or current.get("status") != "pending":
        return None
    if current.get("decision_in_progress"):
        return "An approval decision is currently being forwarded to TrueForge"
    return None


def _has_active_approval_operation(session: dict) -> str | None:
    """Return a human-readable reason if the session has an in-flight
    approval operation, or ``None`` if supersession is safe.

    Must be called under the same session lock as the mutation it guards.

    A ``request_in_flight`` claim with an expired lease is treated as
    abandoned and does *not* block supersession.  The caller that
    detects expiry must clear the stale claim atomically.
    """
    current = session.get("approval_state")
    if not isinstance(current, dict) or current.get("status") != "pending":
        return None
    if current.get("decision_in_progress"):
        return "An approval decision is currently being forwarded to TrueForge"
    if current.get("request_in_flight"):
        # Check lease expiry — a crashed/abandoned request must not block
        # reinvestigation or new approval requests indefinitely.
        request_started = current.get("request_started_at")
        if request_started and isinstance(request_started, str):
            try:
                started = datetime.fromisoformat(
                    request_started.replace("Z", "+00:00")
                )
                age_seconds = (
                    datetime.now(timezone.utc) - started
                ).total_seconds()
                if age_seconds > REQUEST_CLAIM_TIMEOUT_SECONDS:
                    return None  # Lease expired — claim is abandoned
            except (TypeError, ValueError):
                return None  # Invalid timestamp — treat as expired
        else:
            # No timestamp (pre-lease codepath) — treat as expired
            return None
        return "An approval request is currently in flight with TrueForge"
    return None


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
    Raises ``RuntimeError`` if the approval has an active operation that must
    complete before supersession is safe.
    """
    block_reason = _has_active_approval_operation(session)
    if block_reason:
        raise RuntimeError(block_reason)

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
        record.pop("request_started_at", None)

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

    If the approval has an active operation (``decision_in_progress`` or
    ``request_in_flight``), the supersession is *blocked* and the update
    fails with ``success=False`` and ``approval_in_progress=True`` so the
    caller can report a controlled error. The session fields are not
    modified.
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
                # When supersession is requested, check for an active approval
                # operation BEFORE modifying any fields so the check and the
                # field merge are atomic within the same locked mutation.
                if supersede_stale_approval:
                    block_reason = _has_active_approval_operation(s)
                    if block_reason:
                        return {
                            "success": False,
                            "error": block_reason,
                            "approval_in_progress": True,
                        }

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

            target_status = target.get("status")
            if target_status == "superseded":
                return {
                    "success": False,
                    "error": (
                        f"Cannot bind tool_call_id to action with status "
                        f"'superseded' — the action was replaced by a reinvestigation"
                    ),
                }
            # approved/rejected actions CAN receive a late tool_call_id for
            # the legitimate late-forward path (decision completed locally
            # before TrueForge returned with the tool_call_id).
            # pending actions receive a normal binding.

            target["tool_call_id"] = tool_call_id
            target["request_in_flight"] = False  # Unset claim upon binding
            target.pop("request_started_at", None)  # Clear lease timestamp
            if thread_id:
                target["thread_id"] = thread_id

            if ap and ap.get("action_id") == action_id and target is not ap:
                ap["tool_call_id"] = tool_call_id
                ap["request_in_flight"] = False
                ap.pop("request_started_at", None)
                if thread_id:
                    ap["thread_id"] = thread_id

            for action in s.get("actions", []):
                if action.get("action_id") == action_id and action is not target:
                    action["tool_call_id"] = tool_call_id
                    action["request_in_flight"] = False
                    action.pop("request_started_at", None)
                    if thread_id:
                        action["thread_id"] = thread_id
                    target = action if target is None else target

            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            current_status = target.get("status")

            if current_status in ("approved", "rejected"):
                for action in s.get("actions", []):
                    if action.get("action_id") == action_id:
                        # Use forwarding_to_trueforge as a recoverable
                        # claim with an ownership token.  forwarded_to_trueforge
                        # is only set after the TrueForge API call succeeds,
                        # so a crash during forwarding leaves the decision
                        # retryable.
                        if action.get("forwarded_to_trueforge"):
                            return {
                                "success": True,
                                "action_id": action_id,
                                "already_forwarded": True,
                            }
                        if _is_forwarding_claim_active(action):
                            # Another caller holds a fresh claim.
                            return {
                                "success": True,
                                "action_id": action_id,
                                "already_forwarding": True,
                                "forwarding_owner": action.get("forwarding_owner"),
                            }
                        if _forwarding_needs_manual_resolution(action):
                            # A dispatch was attempted under the expired
                            # claim and its outcome is unknown — do not
                            # reclaim and re-POST. See
                            # resolve_uncertain_forwarding().
                            return {
                                "success": False,
                                "error": (
                                    "A previous TrueForge delivery attempt "
                                    "for this decision did not complete "
                                    "before the process restarted, and its "
                                    "outcome is unknown. Manual "
                                    "verification is required before "
                                    "retrying — see "
                                    "resolve_uncertain_forwarding()."
                                ),
                                "uncertain_delivery": True,
                                "action_id": action_id,
                            }
                        # Expired or no claim — acquire fresh.
                        token = str(uuid.uuid4())
                        now_claim = datetime.now(timezone.utc).isoformat()
                        action["forwarding_to_trueforge"] = True
                        action["forwarding_owner"] = token
                        action["forwarding_started_at"] = now_claim
                        action.pop("forwarding_dispatched_at", None)
                        return {
                            "success": True,
                            "action_id": action_id,
                            "pending_decision": current_status,
                            "decided_by": action.get("decided_by"),
                            "forwarding_owner": token,
                        }

            return {"success": True, "action_id": action_id}

        return {"success": False, "error": "Session not found"}

    with forwarding_action_lock(sid, action_id):
        return _mutate_sessions(_set)


def _release_forwarding_claim_unlocked(
    sid: str, action_id: str, error: str, owner_token: str | None = None
) -> dict:
    """Release a forwarding claim. Caller must hold the per-action fence."""

    def _release(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    if owner_token and action.get("forwarding_owner") != owner_token:
                        return {
                            "success": False,
                            "error": "Forwarding claim belongs to another caller",
                            "retryable": False,
                        }
                    action["forwarding_to_trueforge"] = False
                    action["forwarded_to_trueforge"] = False
                    action.pop("forwarding_owner", None)
                    action.pop("forwarding_started_at", None)
                    action.pop("forwarding_dispatched_at", None)
                    action["forward_error"] = error
                    s["updated_at"] = datetime.now(timezone.utc).isoformat()
                    return {"success": True, "action_id": action_id, "retryable": True}
            return {"success": False, "error": "Action not found"}
        return {"success": False, "error": "Session not found"}

    return _mutate_sessions(_release)


def release_forwarding_claim(sid: str, action_id: str, error: str, owner_token: str | None = None) -> dict:
    """Release a late-forward claim after an upstream delivery failure.

    Clears both ``forwarding_to_trueforge`` and ``forwarded_to_trueforge``
    so the decision can be retried on the next TrueForge response.

    If ``owner_token`` is provided, only the claim owner can release it.
    A non-owner release is rejected to prevent one caller from clearing
    another caller's active forwarding claim.
    """
    def _release(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    if owner_token and action.get("forwarding_owner") != owner_token:
                        return {
                            "success": False,
                            "error": "Forwarding claim belongs to another caller",
                            "retryable": False,
                        }
                    action["forwarding_to_trueforge"] = False
                    action["forwarded_to_trueforge"] = False
                    action.pop("forwarding_owner", None)
                    action.pop("forwarding_started_at", None)
                    action.pop("forwarding_dispatched_at", None)
                    action["forward_error"] = error
                    s["updated_at"] = datetime.now(timezone.utc).isoformat()
                    return {"success": True, "action_id": action_id, "retryable": True}
            return {"success": False, "error": "Action not found"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_release)


def complete_forwarding(sid: str, action_id: str, owner_token: str | None = None) -> dict:
    """Transition forwarding_to_trueforge -> forwarded_to_trueforge
    after the TrueForge API call succeeds.

    A crash between set_approval_tool_call_id (which sets forwarding_to_trueforge)
    and this call leaves the decision retryable: forwarding_to_trueforge is True
    but forwarded_to_trueforge is False, so the next call re-enters the late-forward
    path instead of suppressing it.

    If ``owner_token`` is provided, only the claim owner can complete it.
    """
    def _complete(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    if owner_token and action.get("forwarding_owner") != owner_token:
                        return {
                            "success": False,
                            "error": "Forwarding claim belongs to another caller",
                        }
                    action["forwarding_to_trueforge"] = False
                    action["forwarded_to_trueforge"] = True
                    action.pop("forwarding_owner", None)
                    action.pop("forwarding_started_at", None)
                    action.pop("forwarding_dispatched_at", None)
                    action.pop("forward_error", None)
                    s["updated_at"] = datetime.now(timezone.utc).isoformat()
                    return {"success": True, "action_id": action_id}
            return {"success": False, "error": "Action not found"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_complete)


def mark_forwarding_dispatched(sid: str, action_id: str, owner_token: str | None = None) -> dict:
    """Durably record that a TrueForge dispatch is about to be attempted.

    This is the durable "outbox" write for Bug #15: the caller must invoke
    this — and see ``success`` — immediately before issuing the outbound
    POST to TrueForge, under the forwarding claim it already holds.

    Persisting the marker *before* the network call, rather than after, is
    what closes the crash window: if the process dies after TrueForge
    accepts the POST but before ``complete_forwarding`` runs, this marker
    is already on disk. On restart, lease-recovery sees
    ``forwarding_dispatched_at`` set on an expired claim and refuses to
    silently reclaim it (see ``_forwarding_needs_manual_resolution``),
    instead of blindly re-POSTing a decision that may have already been
    delivered. A crash *before* this call (e.g. immediately after the
    claim was acquired, before dispatch even began) leaves no marker
    behind, so that case remains automatically recoverable exactly as
    before.

    If ``owner_token`` is provided, only the current claim owner may set
    the marker — a caller that already lost the lease to a reclaim must
    not be allowed to dispatch under a claim it no longer holds.
    """
    def _mark(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    if not action.get("forwarding_to_trueforge"):
                        return {
                            "success": False,
                            "error": "No active forwarding claim to mark as dispatched",
                        }
                    if owner_token and action.get("forwarding_owner") != owner_token:
                        return {
                            "success": False,
                            "error": "Forwarding claim belongs to another caller",
                        }
                    now = datetime.now(timezone.utc).isoformat()
                    action["forwarding_dispatched_at"] = now
                    s["updated_at"] = now
                    return {"success": True, "action_id": action_id}
            return {"success": False, "error": "Action not found"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_mark)


def resolve_uncertain_forwarding(
    sid: str,
    action_id: str,
    confirmed_delivered: bool,
    resolved_by: str = "operator",
) -> dict:
    """Manually resolve a forwarding claim left uncertain by a crash.

    Only applies to an action currently in the uncertain state produced by
    ``_forwarding_needs_manual_resolution`` (a dispatch marker is set and
    the owning claim's lease has expired without ``complete_forwarding``
    or a release ever running) — this is a deliberate operator action taken
    after checking TrueForge directly out-of-band, not an automatic retry
    path, since TrueForge does not offer an idempotency-key contract that
    would let the system verify this itself.

    ``confirmed_delivered=True`` finalizes the decision as forwarded
    without re-POSTing, so a delivery that already happened is never
    replayed. ``confirmed_delivered=False`` clears the stuck claim so the
    existing ``retry_approval_forwarding`` path can safely re-dispatch —
    the same retry semantics as any other genuinely failed forward.
    """
    def _resolve(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    if not _forwarding_needs_manual_resolution(action):
                        return {
                            "success": False,
                            "error": "Action is not in an uncertain delivery state",
                        }
                    now = datetime.now(timezone.utc).isoformat()
                    action["forwarding_to_trueforge"] = False
                    action.pop("forwarding_owner", None)
                    action.pop("forwarding_started_at", None)
                    action.pop("forwarding_dispatched_at", None)
                    action["forward_resolved_by"] = resolved_by
                    if confirmed_delivered:
                        action["forwarded_to_trueforge"] = True
                        action.pop("forward_error", None)
                    else:
                        action["forwarded_to_trueforge"] = False
                        action["forward_error"] = (
                            "Delivery confirmed not to have reached TrueForge "
                            "after crash recovery; cleared for retry"
                        )
                    s["updated_at"] = now
                    return {
                        "success": True,
                        "action_id": action_id,
                        "forwarded": confirmed_delivered,
                    }
            return {"success": False, "error": "Action not found"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_resolve)


def retry_approval_forwarding(
    sid: str,
    action_id: str,
    tool_call_id: str,
) -> dict:
    """Re-enter the late-forward path for an already terminal action.

    When a late-forward fails and the caller retries, this function:

    1. Locates the original approved/rejected action.
    2. Verifies the tool_call_id matches.
    3. Verifies forwarded_to_trueforge is False (not yet delivered).
    4. Atomically acquires a forwarding claim with a new owner token.
    5. Returns the decision and token needed by approvals.py.

    A new approval action is never created.  The original terminal action
    is reused so the decision and tool_call_id remain bound.
    """
    def _retry(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue

            # Locate the action in the session's action history.
            target = None
            for action in s.get("actions", []):
                if action.get("action_id") == action_id:
                    target = action
                    break

            if target is None:
                return {"success": False, "error": "Action not found"}

            status = target.get("status")
            if status not in ("approved", "rejected"):
                return {
                    "success": False,
                    "error": (
                        f"Cannot retry forwarding for action with status "
                        f"'{status}' — must be approved or rejected"
                    ),
                }

            if target.get("tool_call_id") != tool_call_id:
                return {
                    "success": False,
                    "error": "tool_call_id does not match the original action",
                }

            if target.get("forwarded_to_trueforge"):
                return {
                    "success": False,
                    "error": "Decision was already forwarded to TrueForge",
                }

            if _is_forwarding_claim_active(target):
                return {
                    "success": True,
                    "action_id": action_id,
                    "already_forwarding": True,
                    "forwarding_owner": target.get("forwarding_owner"),
                }

            if _forwarding_needs_manual_resolution(target):
                # A dispatch was actually attempted under the now-expired
                # claim. We cannot tell whether it reached TrueForge, so we
                # must not silently reclaim and re-POST — that could
                # deliver the same decision twice. Surface the uncertainty
                # instead; see resolve_uncertain_forwarding().
                return {
                    "success": False,
                    "error": (
                        "A previous TrueForge delivery attempt for this "
                        "decision did not complete before the process "
                        "restarted, and its outcome is unknown. Manual "
                        "verification is required before retrying — see "
                        "resolve_uncertain_forwarding()."
                    ),
                    "uncertain_delivery": True,
                    "action_id": action_id,
                }

            # Expired or no claim, and no dispatch was attempted under it
            # — safe to atomically acquire a fresh forwarding claim.
            token = str(uuid.uuid4())
            now_claim = datetime.now(timezone.utc).isoformat()
            target["forwarding_to_trueforge"] = True
            target["forwarding_owner"] = token
            target["forwarding_started_at"] = now_claim
            target.pop("forwarding_dispatched_at", None)
            target.pop("forward_error", None)
            s["updated_at"] = now_claim

            return {
                "success": True,
                "action_id": action_id,
                "pending_decision": status,
                "decided_by": target.get("decided_by", "analyst"),
                "forwarding_owner": token,
            }

        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_retry)


def persist_trueforge_session_id(sid: str, tf_session_id: str) -> dict:
    """Atomically persist a TrueForge session ID on the local session."""
    if not tf_session_id or not isinstance(tf_session_id, str):
        return {"success": False, "error": "tf_session_id must be a non-empty string"}
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
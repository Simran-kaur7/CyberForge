"""Regression tests for TrueForge uncertain-forwarding serialization.

These tests assume the repository's existing sdk_client persistence helpers.
They can be run with pytest from the repository root.
"""

from datetime import datetime, timedelta, timezone
import multiprocessing
import threading
import time

from app import sdk_client
import app.api.approvals as approvals
def _prepare_uncertain_action():
    session = sdk_client.create_session("INC-RACE")
    sid = session["id"]
    result = sdk_client.request_approval(
        sid, "BLOCK_IP", {"ip": "10.0.0.25"}
    )
    aid = result["action_id"]
    sdk_client.release_request_claim(sid, aid)
    sdk_client.approve_action(sid, aid)
    claim = sdk_client.set_approval_tool_call_id(sid, aid, "tc-race")
    assert claim["success"] is True
    token = claim["forwarding_owner"]
    sdk_client.mark_forwarding_dispatched(sid, aid, owner_token=token)
    sdk_client.mark_forwarding_uncertain(
        sid, aid, "simulated ambiguous delivery", owner_token=token
    )
    return sid, aid, token


def _age_claim(sid, aid):
    old = (
        datetime.now(timezone.utc)
        - timedelta(seconds=sdk_client.FORWARDING_CLAIM_TIMEOUT_SECONDS + 60)
    ).isoformat()

    def mutate(sessions):
        for session in sessions:
            if session["id"] != sid:
                continue
            for action in session["actions"]:
                if action["action_id"] == aid:
                    action["forwarding_started_at"] = old

    sdk_client._mutate_sessions(mutate)


def _hold_forwarding_fence(sid, aid, ready, release):
    from app import sdk_client as worker_sdk

    with worker_sdk.forwarding_action_lock(sid, aid):
        ready.set()
        release.wait(timeout=10)


def _resolve_uncertain_in_process(sid, aid, result_queue):
    from app import sdk_client as resolver_sdk

    result_queue.put(
        resolver_sdk.resolve_uncertain_forwarding(
            sid, aid, False, resolved_by="operator"
        )
    )


def _worker_mark_uncertain_in_process(sid, aid, token, ready, persisted, release):
    from app import sdk_client as worker_sdk

    with worker_sdk.forwarding_action_lock(sid, aid):
        ready.set()
        result = worker_sdk._mark_forwarding_uncertain_locked(
            sid,
            aid,
            "connection reset",
            owner_token=token,
        )
        assert result["success"] is True
        persisted.set()
        release.wait(timeout=10)


def test_manual_resolution_uses_forwarding_fence():
    """Manual resolution must block while another process owns the fence."""
    sid, aid, _ = _prepare_uncertain_action()

    ctx = multiprocessing.get_context("spawn")
    entered = ctx.Event()
    release = ctx.Event()
    result_queue = ctx.Queue()

    worker = ctx.Process(
        target=_hold_forwarding_fence,
        args=(sid, aid, entered, release),
    )
    resolver = ctx.Process(
        target=_resolve_uncertain_in_process,
        args=(sid, aid, result_queue),
    )

    worker.start()
    assert entered.wait(timeout=5)

    resolver.start()
    time.sleep(0.3)
    assert resolver.is_alive(), "resolver bypassed the inter-process fence"

    release.set()
    worker.join(timeout=5)
    resolver.join(timeout=5)

    assert worker.exitcode == 0
    assert resolver.exitcode == 0
    result = result_queue.get(timeout=2)
    assert result["success"] is True


def test_worker_and_manual_resolution_are_serialized():
    """Manual resolution cannot clear state before worker outcome is persisted."""
    sid, aid, token = _prepare_uncertain_action()

    # Restore the state immediately before the worker's POST: the dispatch
    # marker exists, but no final/uncertain outcome has been persisted yet.
    def reset_uncertainty(sessions):
        for session in sessions:
            if session["id"] == sid:
                for action in session["actions"]:
                    if action["action_id"] == aid:
                        action.pop("forwarding_outcome", None)
                        action.pop("forwarding_uncertain_at", None)

    sdk_client._mutate_sessions(reset_uncertainty)

    ctx = multiprocessing.get_context("spawn")
    worker_ready = ctx.Event()
    worker_persisted = ctx.Event()
    release = ctx.Event()
    result_queue = ctx.Queue()

    worker = ctx.Process(
        target=_worker_mark_uncertain_in_process,
        args=(sid, aid, token, worker_ready, worker_persisted, release),
    )
    resolver = ctx.Process(
        target=_resolve_uncertain_in_process,
        args=(sid, aid, result_queue),
    )

    worker.start()
    assert worker_ready.wait(timeout=5)

    resolver.start()
    time.sleep(0.3)
    assert resolver.is_alive(), "resolver mutated state before worker released fence"

    assert worker_persisted.wait(timeout=5)

    # The worker has persisted the ambiguous outcome, but still owns the fence.
    # Resolution must remain blocked until the worker's fenced lifecycle ends.
    time.sleep(0.2)
    assert resolver.is_alive()

    release.set()
    worker.join(timeout=5)
    resolver.join(timeout=5)

    assert worker.exitcode == 0
    assert resolver.exitcode == 0
    result = result_queue.get(timeout=2)
    assert result["success"] is True

    action = next(
        a for a in sdk_client.get_session(sid)["actions"]
        if a["action_id"] == aid
    )
    assert action["forwarding_to_trueforge"] is False
    assert action.get("forwarding_owner") is None

def test_resolve_not_delivered_then_retry_is_safe():
    sid, aid, _ = _prepare_uncertain_action()

    result = sdk_client.resolve_uncertain_forwarding(
        sid, aid, False, resolved_by="operator"
    )
    assert result["success"] is True

    retry = sdk_client.retry_approval_forwarding(sid, aid, "tc-race")
    assert retry["success"] is True
    assert retry["forwarding_owner"]

    action = next(
        a for a in sdk_client.get_session(sid)["actions"]
        if a["action_id"] == aid
    )
    assert action.get("forwarding_owner") == retry["forwarding_owner"]
    assert action.get("forwarding_dispatched_at") is None


def test_ambiguous_failure_does_not_clear_dispatch_marker():
    sid, aid, token = _prepare_uncertain_action()
    action_before = next(
        a for a in sdk_client.get_session(sid)["actions"]
        if a["action_id"] == aid
    )
    marker = action_before["forwarding_dispatched_at"]

    result = sdk_client.mark_forwarding_uncertain(
        sid, aid, "timeout/connection reset", owner_token=token
    )
    assert result["success"] is True
    assert result["uncertain_delivery"] is True
    assert result["retryable"] is False

    action = next(
        a for a in sdk_client.get_session(sid)["actions"]
        if a["action_id"] == aid
    )
    assert action["forwarding_dispatched_at"] == marker
    assert action["forwarding_outcome"] == "uncertain"


def test_pre_dispatch_failure_remains_retryable():
    session = sdk_client.create_session("INC-PRE-DISPATCH")
    sid = session["id"]
    result = sdk_client.request_approval(
        sid, "BLOCK_IP", {"ip": "10.0.0.25"}
    )
    aid = result["action_id"]
    sdk_client.release_request_claim(sid, aid)
    sdk_client.approve_action(sid, aid)
    claim = sdk_client.set_approval_tool_call_id(sid, aid, "tc-pre")
    assert claim["success"] is True

    # Failure before mark_forwarding_dispatched is a definite failure.
    released = sdk_client.release_forwarding_claim(
        sid, aid, "pre-dispatch failure",
        owner_token=claim["forwarding_owner"],
    )
    assert released["success"] is True
    assert released["retryable"] is True

    action = next(
        a for a in sdk_client.get_session(sid)["actions"]
        if a["action_id"] == aid
    )
    assert action.get("forwarding_dispatched_at") is None
    retry = sdk_client.retry_approval_forwarding(sid, aid, "tc-pre")
    assert retry["success"] is True


def _prepare_retryable_forwarding_action():
    session = sdk_client.create_session("INC-SSE-FAIL")
    sid = session["id"]
    result = sdk_client.request_approval(
        sid, "BLOCK_IP", {"ip": "10.0.0.26"}
    )
    aid = result["action_id"]
    sdk_client.release_request_claim(sid, aid)
    sdk_client.approve_action(sid, aid)
    claim = sdk_client.set_approval_tool_call_id(sid, aid, "tc-sse-fail")
    assert claim["success"] is True
    return sid, aid, claim["forwarding_owner"]


def test_ambiguous_exception_path_does_not_self_deadlock():
    """A post-dispatch exception persists uncertainty and returns promptly."""
    sid, aid, token = _prepare_retryable_forwarding_action()
    sdk_client.mark_forwarding_dispatched(sid, aid, owner_token=token)

    result = {}

    def worker():
        result["value"] = sdk_client._mark_forwarding_uncertain_locked(
            sid, aid, "connection reset", owner_token=token
        )

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=5)

    assert not t.is_alive()
    assert result["value"]["success"] is True
    assert result["value"]["uncertain_delivery"] is True
    assert result["value"]["retryable"] is False


def test_late_forward_turn_failed_is_retryable(monkeypatch):
    """An explicit TrueForge turn.failed event is definite failure, not delivered."""
    sid, aid, token = _prepare_retryable_forwarding_action()

    monkeypatch.setattr(
        approvals,
        "_tf_post_sse",
        lambda *args, **kwargs: {
            "type": "turn.failed",
            "error": "tool execution failed",
        },
    )

    # Exercise the state transition directly under the same fence because
    # the API's TrueForge session verification is unrelated to this regression.
    with sdk_client.forwarding_action_lock(sid, aid):
        sdk_client.mark_forwarding_dispatched(sid, aid, owner_token=token)
        event = approvals._tf_post_sse("/ignored", {})
        assert event["type"] == "turn.failed"
        released = sdk_client._release_forwarding_claim_locked(
            sid, aid, "TrueForge reported turn.failed", owner_token=token
        )

    assert released["success"] is True
    assert released["retryable"] is True
    action = next(a for a in sdk_client.get_session(sid)["actions"] if a["action_id"] == aid)
    assert action.get("forwarding_dispatched_at") is None
    assert action.get("forwarding_to_trueforge") is False
    assert action.get("forwarded_to_trueforge") is False


def test_late_forward_error_event_is_retryable(monkeypatch):
    """An explicit TrueForge error event is definite failure, not delivered."""
    sid, aid, token = _prepare_retryable_forwarding_action()
    monkeypatch.setattr(
        approvals,
        "_tf_post_sse",
        lambda *args, **kwargs: {"type": "error", "error": "upstream rejected turn"},
    )

    with sdk_client.forwarding_action_lock(sid, aid):
        sdk_client.mark_forwarding_dispatched(sid, aid, owner_token=token)
        event = approvals._tf_post_sse("/ignored", {})
        assert event["type"] == "error"
        released = sdk_client._release_forwarding_claim_locked(
            sid, aid, "TrueForge reported error", owner_token=token
        )

    assert released["success"] is True
    assert released["retryable"] is True
    action = next(a for a in sdk_client.get_session(sid)["actions"] if a["action_id"] == aid)
    assert action.get("forwarding_dispatched_at") is None
    assert action.get("forwarded_to_trueforge") is False

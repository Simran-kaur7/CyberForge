"""Regression tests for TrueForge uncertain-forwarding serialization.

These tests assume the repository's existing sdk_client persistence helpers.
They can be run with pytest from the repository root.
"""

from datetime import datetime, timedelta, timezone
import threading
import time

from app import sdk_client
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


def test_manual_resolution_uses_forwarding_fence():
    """Resolution blocks while the worker owns the per-action fence."""
    sid, aid, _ = _prepare_uncertain_action()

    entered = threading.Event()
    release = threading.Event()

    def worker():
        with sdk_client.forwarding_action_lock(sid, aid):
            entered.set()
            release.wait(timeout=5)

    t = threading.Thread(target=worker)
    t.start()
    assert entered.wait(timeout=5)

    result = {}

    def resolver():
        result["value"] = sdk_client.resolve_uncertain_forwarding(
            sid, aid, False, resolved_by="operator"
        )

    r = threading.Thread(target=resolver)
    r.start()
    time.sleep(0.2)
    assert r.is_alive(), "resolver mutated state without waiting for the fence"

    release.set()
    t.join(timeout=5)
    r.join(timeout=5)

    assert not r.is_alive()
    assert result["value"]["success"] is True


def test_worker_and_manual_resolution_are_serialized(monkeypatch):
    """A paused worker cannot be cleared by resolution before its POST outcome."""
    sid, aid, token = _prepare_uncertain_action()

    # Re-create the pre-POST state: dispatch marker is present but outcome is
    # not yet uncertain, matching the worker pause described by the bug.
    def reset_uncertainty(sessions):
        for session in sessions:
            if session["id"] == sid:
                for action in session["actions"]:
                    if action["action_id"] == aid:
                        action.pop("forwarding_outcome", None)
                        action.pop("forwarding_uncertain_at", None)

    sdk_client._mutate_sessions(reset_uncertainty)

    worker_entered = threading.Event()
    allow_post = threading.Event()
    resolver_started = threading.Event()
    resolver_done = threading.Event()
    events = []

    def worker():
        with sdk_client.forwarding_action_lock(sid, aid):
            worker_entered.set()
            allow_post.wait(timeout=5)
            # Simulate the ambiguous POST result and persist uncertainty
            # before releasing the fence. Use the unlocked persistence primitive
            # here because mark_forwarding_uncertain() itself acquires the same
            # fence and would otherwise self-deadlock.
            def persist_uncertain(sessions):
                for session in sessions:
                    if session["id"] == sid:
                        for action in session["actions"]:
                            if action["action_id"] == aid:
                                action["forwarding_outcome"] = "uncertain"
                                action["forwarding_uncertain_at"] = datetime.now(timezone.utc).isoformat()
                                action["forward_error"] = "connection reset"
                                return

            sdk_client._mutate_sessions(persist_uncertain)
            events.append("worker_uncertain")

    def resolver():
        resolver_started.set()
        result = sdk_client.resolve_uncertain_forwarding(
            sid, aid, False, resolved_by="operator"
        )
        assert result["success"] is True
        events.append("resolver")
        resolver_done.set()

    wt = threading.Thread(target=worker)
    wt.start()
    assert worker_entered.wait(timeout=5)

    rt = threading.Thread(target=resolver)
    rt.start()
    assert resolver_started.wait(timeout=5)
    time.sleep(0.2)
    assert not resolver_done.is_set()

    # Worker completes its fenced lifecycle first.
    allow_post.set()
    wt.join(timeout=5)
    rt.join(timeout=5)

    assert events == ["worker_uncertain", "resolver"]
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

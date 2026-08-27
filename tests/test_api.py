"""Tests for CyberForge SDK Client (session & approval management)."""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def assert_eq(a, b):
    assert a == b, f"Expected {b!r}, got {a!r}"


def run_all():
    from app import sdk_client
    from app.api.approvals import _require_api_key
    import app.api.approvals as approvals_mod

    passed = 0
    failed = 0
    errors = []

    def check(name, fn):
        nonlocal passed, failed
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
            errors.append(f"{name}: {e}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_sessions = Path(tmpdir) / "sessions.json"
        original = sdk_client.SESSIONS_FILE
        sdk_client.SESSIONS_FILE = tmp_sessions

        try:
            # 1: Empty list
            def t1():
                assert_eq(sdk_client.list_sessions(), [])
            check("test_list_empty", t1)

            # 2: Create session
            session = [None]
            def t2():
                session[0] = sdk_client.create_session("INC-1024", {"source_ip": "10.0.0.25"})
                assert session[0]["incident_id"] == "INC-1024"
                assert session[0]["status"] == "active"
                assert len(session[0]["id"]) == 8
            check("test_create_session", t2)

            sid = session[0]["id"]

            # 3: Get by ID
            def t3():
                assert_eq(sdk_client.get_session(sid)["incident_id"], "INC-1024")
            check("test_get_session", t3)

            # 4: List shows one
            def t4():
                assert_eq(len(sdk_client.list_sessions()), 1)
            check("test_list_sessions", t4)

            # 5: Find by incident
            def t5():
                assert_eq(sdk_client.find_session_by_incident("INC-1024")["id"], sid)
            check("test_find_by_incident", t5)

            # 6: Request approval
            aid = [None]
            def t6():
                r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
                assert r["success"] is True
                assert r["status"] == "pending"
                aid[0] = r["action_id"]
            check("test_request_approval", t6)

            # 7: Second request blocked while pending
            def t7():
                r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
                assert r["success"] is False
            check("test_second_request_blocked", t7)

            # 8: Approve
            def t8():
                assert_eq(sdk_client.approve_action(sid, aid[0])["status"], "approved")
            check("test_approve_action", t8)

            # 9: Can't approve again
            def t9():
                r = sdk_client.approve_action(sid, aid[0])
                assert r["success"] is False
            check("test_cannot_re_approve", t9)

            # 10: Session reflects approval
            def t10():
                assert_eq(sdk_client.get_session(sid)["approval_state"]["status"], "approved")
            check("test_session_reflects_approval", t10)

            # 11: Request then reject
            aid2 = [None]
            def t11():
                r = sdk_client.request_approval(sid, "ISOLATE_HOST", {"host": "web-01"})
                aid2[0] = r["action_id"]
            check("test_request_approval_2", t11)

            def t12():
                assert_eq(sdk_client.reject_action(sid, aid2[0])["status"], "rejected")
            check("test_reject_action", t12)

            # 13: Can't reject again
            def t13():
                r = sdk_client.reject_action(sid, aid2[0])
                assert r["success"] is False
            check("test_cannot_re_reject", t13)

            # 14: Nonexistent session
            def t14():
                assert sdk_client.get_session("nope") is None
            check("test_nonexistent_session", t14)

            # 15: update_session success
            def t15():
                r = sdk_client.update_session(sid, evidence_snapshot={"updated": True})
                assert r["success"] is True
                s = sdk_client.get_session(sid)
                assert s["evidence_snapshot"]["updated"] is True
            check("test_update_session_success", t15)

            # 16: update_session nonexistent
            def t16():
                r = sdk_client.update_session("nope", evidence_snapshot={})
                assert r["success"] is False
            check("test_update_session_nonexistent", t16)

            # 17: _read_sessions consistent
            def t17():
                sessions = sdk_client._read_sessions()
                assert len(sessions) >= 1
                ids = [s["id"] for s in sessions]
                assert sid in ids
            check("test_read_sessions_consistent", t17)

            # 18: Concurrent create safety
            def t18():
                s1 = sdk_client.create_session("INC-TEST-A")
                s2 = sdk_client.create_session("INC-TEST-B")
                all_sessions = sdk_client.list_sessions()
                all_ids = [s["id"] for s in all_sessions]
                assert s1["id"] in all_ids
                assert s2["id"] in all_ids
            check("test_concurrent_create", t18)

            # 19: find by incident returns most recent
            def t19():
                s = sdk_client.find_session_by_incident("INC-TEST-A")
                assert s is not None
                assert s["incident_id"] == "INC-TEST-A"
            check("test_find_by_incident_latest", t19)

            # 20: Corrupted sessions file
            def t20():
                bad_file = Path(tmpdir) / "bad_sessions.json"
                bad_file.write_text("not valid json {{{")
                original_file = sdk_client.SESSIONS_FILE
                sdk_client.SESSIONS_FILE = bad_file
                try:
                    result = sdk_client._load_sessions()
                    assert result == []
                    assert bad_file.with_suffix(".json.corrupted").exists()
                finally:
                    sdk_client.SESSIONS_FILE = original_file
            check("test_corrupted_sessions", t20)

            # 21: Atomic write
            def t21():
                atomic_file = Path(tmpdir) / "atomic.json"
                original_file = sdk_client.SESSIONS_FILE
                sdk_client.SESSIONS_FILE = atomic_file
                try:
                    sdk_client._save_sessions([])
                    assert atomic_file.exists()
                    assert sdk_client._load_sessions() == []
                finally:
                    sdk_client.SESSIONS_FILE = original_file
            check("test_atomic_write", t21)

        finally:
            sdk_client.SESSIONS_FILE = original

    # --- Approval auth tests (outside temp dir) ---

    orig_key = approvals_mod.EXPECTED_API_KEY

    # 22: Valid Bearer token
    def t22():
        approvals_mod.EXPECTED_API_KEY = "test-secret-key"
        try:
            result = _require_api_key("Bearer test-secret-key")
            assert result == "analyst"
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_auth_valid_bearer", t22)

    # 23: Missing header → 401
    def t23():
        from app.api.approvals import HTTPException
        approvals_mod.EXPECTED_API_KEY = "test-key"
        try:
            try:
                _require_api_key(None)
                assert False, "Should have raised"
            except HTTPException as e:
                assert e.status_code == 401
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_auth_missing_header", t23)

    # 24: Malformed header (no Bearer prefix) → 401
    def t24():
        from app.api.approvals import HTTPException
        approvals_mod.EXPECTED_API_KEY = "test-key"
        try:
            try:
                _require_api_key("Token abc123")
                assert False, "Should have raised"
            except HTTPException as e:
                assert e.status_code == 401
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_auth_malformed_header", t24)

    # 25: Empty token → 401
    def t25():
        from app.api.approvals import HTTPException
        approvals_mod.EXPECTED_API_KEY = "test-key"
        try:
            try:
                _require_api_key("Bearer ")
                assert False, "Should have raised"
            except HTTPException as e:
                assert e.status_code == 401
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_auth_empty_token", t25)

    # 26: Wrong token → 403
    def t26():
        from app.api.approvals import HTTPException
        approvals_mod.EXPECTED_API_KEY = "test-key"
        try:
            try:
                _require_api_key("Bearer wrong-token")
                assert False, "Should have raised"
            except HTTPException as e:
                assert e.status_code == 403
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_auth_wrong_token", t26)

    # 27: No API key configured → dev bypass
    def t27():
        approvals_mod.EXPECTED_API_KEY = ""
        try:
            result = _require_api_key(None)
            assert result == "analyst-local-dev"
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_auth_no_key_dev_bypass", t27)

    # 28: Bearer with extra spaces
    def t28():
        approvals_mod.EXPECTED_API_KEY = "test-key"
        try:
            result = _require_api_key("Bearer  test-key  ")
            assert result == "analyst"
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_auth_bearer_extra_spaces", t28)



    # --- Targeted API semantics tests ---
    def t29():
        import app.api.approvals as approvals_mod
        approvals_mod.EXPECTED_API_KEY = "pending-key"
        try:
            try:
                approvals_mod.get_pending_approvals(None)
                assert False, "Pending approvals should require authentication"
            except Exception as e:
                from app.api.approvals import HTTPException
                assert isinstance(e, HTTPException)
                assert e.status_code == 401
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_pending_approvals_requires_auth", t29)

    def t30():
        import app.api.approvals as approvals_mod
        approvals_mod.EXPECTED_API_KEY = "pending-key"
        try:
            with patch.object(approvals_mod, "_tf_get", return_value=[]):
                result = approvals_mod.get_pending_approvals("Bearer pending-key")
                assert result == {"count": 0, "approvals": []}
        finally:
            approvals_mod.EXPECTED_API_KEY = orig_key
    check("test_pending_approvals_authenticated", t30)

    def t31():
        import app.api.incidents as incidents_mod
        from app.api.approvals import HTTPException
        fake_analysis = {"success": True, "source_ip": "10.0.0.25", "findings": [], "risk_indicators": {}}
        fake_logs = {"success": True, "failed_logins": 1, "successful_logins": 0, "match_count": 1}
        fake_activity = {"success": True, "process_count": 1, "suspicious_process_count": 0, "unusual_connection_count": 0}
        fake_session = {"id": "sess123", "incident_id": "INC-1024", "trueforge_session_id": None}
        with patch.object(incidents_mod, "analyze_evidence", return_value=fake_analysis), \
             patch.object(incidents_mod, "search_security_logs", return_value=fake_logs), \
             patch.object(incidents_mod, "check_system_activity", return_value=fake_activity), \
             patch.object(incidents_mod, "find_session_by_incident", return_value=fake_session), \
             patch.object(incidents_mod, "update_session", return_value={"success": False, "error": "write failed"}), \
             patch.object(incidents_mod, "_require_successful_tool_result", side_effect=lambda result, name: result):
            try:
                incidents_mod.investigate_incident("INC-1024")
                assert False, "Persistence failure should not report success"
            except HTTPException as e:
                assert e.status_code == 503
                assert e.detail == "Investigation session could not be persisted."
    check("test_session_persistence_failure_is_controlled", t31)

    # ---------------------------------------------------------------
    # /api/investigate session lifecycle
    # ---------------------------------------------------------------
    def make_fake_result(target_ip="10.0.0.25", query="Investigate suspicious activity"):
        """A complete, containment-capable investigation result."""
        return {
            "success": True,
            "status": "complete",
            "evidence_complete": True,
            "query": query,
            "target_ip": target_ip,
            "severity": "HIGH",
            "risk_score": {"score": 80, "level": "HIGH", "max_score": 100, "breakdown": {}},
            "findings": ["test"],
            "evidence": ["evidence"],
            "tools_used": ["test"],
            "recommendation": "test",
            "containment_allowed": True,
            "tool_results": {"correlated_analysis": {"available": True}},
            "errors": {"log_search": None, "system_activity": None, "analysis": None},
        }

    def with_temp_sessions(fn):
        """Run fn(sdk_client) against an isolated sessions store."""
        import tempfile
        from pathlib import Path
        from app import sdk_client

        original_sessions = sdk_client.SESSIONS_FILE
        with tempfile.TemporaryDirectory() as tmpdir:
            sdk_client.SESSIONS_FILE = Path(tmpdir) / "sessions.json"
            try:
                return fn(sdk_client)
            finally:
                sdk_client.SESSIONS_FILE = original_sessions

    # 32: session is keyed on the caller-supplied incident id, not the query
    def t32():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                result = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-1024"
                ))
            assert "session_id" in result, f"Missing session_id in: {list(result.keys())}"
            assert result["session_id"] is not None
            assert len(result["session_id"]) == 8
            assert result["incident_id"] == "INC-1024"
            sess = sdk_client.get_session(result["session_id"])
            assert sess is not None
            assert sess["incident_id"] == "INC-1024"
            assert sess["query"] == "Investigate 10.0.0.25"
            assert sess["target_ip"] == "10.0.0.25"
            # Evidence and risk are persisted in the creating mutation
            assert sess["risk_score"]["score"] == 80
            assert sess["evidence_snapshot"] == {"correlated_analysis": {"available": True}}

        with_temp_sessions(body)
    check("test_investigate_session_keyed_on_incident_id", t32)

    # 33: identical query text must never merge distinct investigations
    def t33():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            def run(target):
                with patch(
                    "app.api.investigate.run_investigation",
                    return_value=make_fake_result(target_ip=target),
                ):
                    return investigate(InvestigationRequest(
                        query="Investigate suspicious activity", target_ip=target
                    ))["session_id"]

            first = run("10.0.0.25")
            other_target = run("192.168.1.50")
            same_target_again = run("10.0.0.25")

            # Same query, different targets → independent sessions
            assert first != other_target, "Distinct targets must not share a session"
            # Without an incident id there is no stable key, so never reuse
            assert same_target_again != first
            incident_ids = {
                sdk_client.get_session(i)["incident_id"]
                for i in (first, other_target, same_target_again)
            }
            assert len(incident_ids) == 3, f"Sessions collided: {incident_ids}"
            # The free-form query must not become the session key
            for iid in incident_ids:
                assert "Investigate suspicious activity" not in iid

        with_temp_sessions(body)
    check("test_same_query_does_not_merge_sessions", t33)

    # 34: explicit incident id reuses a session, but only for the same target
    def t34():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            def run(target):
                with patch(
                    "app.api.investigate.run_investigation",
                    return_value=make_fake_result(target_ip=target),
                ):
                    return investigate(InvestigationRequest(
                        query="Investigate suspicious activity",
                        target_ip=target,
                        incident_id="INC-2048",
                    ))["session_id"]

            first = run("10.0.0.25")
            again = run("10.0.0.25")
            other_target = run("192.168.1.50")

            # Same incident + target → the approval lifecycle continues
            assert first == again
            # Same incident, different target → must not overwrite the first
            assert other_target != first
            assert sdk_client.get_session(first)["target_ip"] == "10.0.0.25"
            assert sdk_client.get_session(other_target)["target_ip"] == "192.168.1.50"

        with_temp_sessions(body)
    check("test_incident_id_reuse_is_target_scoped", t34)

    # 35: a failed session update must not return a containment-capable session
    def t35():
        from app.api.investigate import investigate, InvestigationRequest
        from app.api.approvals import HTTPException

        def body(sdk_client):
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                first = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-4096"
                ))
            assert first["session_id"]

            failed = make_fake_result()
            with patch("app.api.investigate.run_investigation", return_value=failed), \
                 patch("app.api.investigate.update_session",
                       return_value={"success": False, "error": "write failed"}):
                try:
                    investigate(InvestigationRequest(
                        query="Investigate 10.0.0.25", incident_id="INC-4096"
                    ))
                    assert False, "Persistence failure should not report success"
                except HTTPException as e:
                    assert e.status_code == 503
                    assert e.detail == "Investigation session could not be persisted."
            # No usable session id may leak to the caller
            assert "session_id" not in failed

        with_temp_sessions(body)
    check("test_investigate_persistence_failure_is_controlled", t35)

    # 36: an unwritable session store is a controlled 503, not a 500/success
    def t36():
        from app.api.investigate import investigate, InvestigationRequest
        from app.api.approvals import HTTPException

        def body(sdk_client):
            fake = make_fake_result()
            with patch("app.api.investigate.run_investigation", return_value=fake), \
                 patch("app.api.investigate.create_session", side_effect=OSError("disk full")):
                try:
                    investigate(InvestigationRequest(query="Investigate 10.0.0.25"))
                    assert False, "Unwritable session store should not report success"
                except HTTPException as e:
                    assert e.status_code == 503
            assert "session_id" not in fake

        with_temp_sessions(body)
    check("test_investigate_session_write_error_is_controlled", t36)

    # 37: malformed incident ids are rejected before any session work
    def t37():
        from app.api.investigate import (
            investigate,
            InvestigationRequest,
            _normalize_incident_id,
            MAX_INCIDENT_ID_LENGTH,
        )
        from app.api.approvals import HTTPException

        assert _normalize_incident_id(None) is None
        assert _normalize_incident_id("   ") is None
        assert _normalize_incident_id("  INC-1024 ") == "INC-1024"
        for bad in ("INC 1024", "INC/1024", "INC\n1024", "a" * (MAX_INCIDENT_ID_LENGTH + 1), 42):
            try:
                _normalize_incident_id(bad)
                assert False, f"Expected rejection for {bad!r}"
            except HTTPException as e:
                assert e.status_code == 422

        def body(sdk_client):
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                try:
                    investigate(InvestigationRequest(
                        query="Investigate 10.0.0.25", incident_id="INC 1024"
                    ))
                    assert False, "Expected 422 for a malformed incident_id"
                except HTTPException as e:
                    assert e.status_code == 422

        with_temp_sessions(body)
    check("test_investigate_rejects_malformed_incident_id", t37)

    # 38: session store helpers reject unusable keys and protected writes
    def t38():
        def body(sdk_client):
            created = sdk_client.create_session("INC-8192", {"a": 1}, risk_score={"score": 10})
            assert created["risk_score"] == {"score": 10}
            # An absent incident id must never match an existing session
            assert sdk_client.find_session_by_incident(None) is None
            assert sdk_client.find_session_by_incident("") is None
            # Identity and approval state cannot be clobbered by a bulk update
            for field in ("id", "incident_id", "approval_state", "actions"):
                r = sdk_client.update_session(created["id"], **{field: "hijacked"})
                assert r["success"] is False, f"{field} should be protected"
            assert sdk_client.get_session(created["id"])["incident_id"] == "INC-8192"
            assert sdk_client.update_session(created["id"])["success"] is False
            assert sdk_client.update_session("", risk_score={})["success"] is False

        with_temp_sessions(body)
    check("test_session_store_key_and_field_guards", t38)

    # ------------------------------------------------------------------
    # 39-48: Race condition regression tests
    # ------------------------------------------------------------------

    # 39: Reinvestigation rejected while decision_in_progress exists
    def t39():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r["success"] is True
            aid = r["action_id"]
            # Simulate a decision being forwarded
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            assert pr["success"] is True
            # Reinvestigation must be blocked
            ur = sdk_client.update_session(
                sid, supersede_stale_approval=True,
                evidence_snapshot={"replaced": True}
            )
            assert ur["success"] is False, "Reinvestigation must not proceed during decision forwarding"
            assert ur.get("approval_in_progress") is True
            # Session fields must NOT have been modified
            sess = sdk_client.get_session(sid)
            assert sess["evidence_snapshot"] == {}, "Session was mutated despite blocked supersession"
            # Approval must still be pending with decision_in_progress intact
            assert sess["approval_state"]["status"] == "pending"
            assert sess["approval_state"].get("decision_in_progress") is not None
    check("test_reinvestigation_rejected_with_decision_in_progress", t39)

    # 40: Reinvestigation rejected while request_in_flight exists
    def t40():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-2")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r["success"] is True
            # Approval was created with request_in_flight=True by request_approval
            # Reinvestigation must be blocked
            ur = sdk_client.update_session(
                sid, supersede_stale_approval=True,
                evidence_snapshot={"replaced": True}
            )
            assert ur["success"] is False, "Reinvestigation must not proceed while request is in flight"
            assert ur.get("approval_in_progress") is True
            sess = sdk_client.get_session(sid)
            assert sess["evidence_snapshot"] == {}, "Session was mutated despite blocked supersession"
            assert sess["approval_state"]["status"] == "pending"
    check("test_reinvestigation_rejected_with_request_in_flight", t40)

    # 41: Stale action cannot receive a tool_call_id
    def t41():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-3")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            # Simulate reinvestigation superseding (no active operation, so it succeeds)
            sdk_client.release_request_claim(sid, aid)  # Clear request_in_flight
            ur = sdk_client.update_session(
                sid, supersede_stale_approval=True,
                evidence_snapshot={"new": True}
            )
            assert ur["success"] is True
            assert ur.get("superseded_action_id") == aid
            # Late TrueForge response tries to bind tool_call_id
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tf-call-123")
            assert br["success"] is False, "Must not bind tool_call_id to superseded action"
            assert "superseded" in br["error"]
    check("test_stale_action_rejects_tool_call_id_binding", t41)

    # 42: Late approved decision forwards tool_call_id (legitimate late-forward)
    def t42():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-4")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            # Approve the action
            ar = sdk_client.approve_action(sid, aid)
            assert ar["status"] == "approved"
            # Late TrueForge response tries to bind — must succeed for late-forward
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tf-call-456")
            assert br["success"] is True, "Late binding to approved action must succeed"
            assert br.get("pending_decision") == "approved"
            # Forwarded exactly once
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tf-call-456")
            assert br2["success"] is True
            assert br2.get("already_forwarded") is True
    check("test_late_approved_forwards_tool_call_id", t42)

    # 43: Pending approval remains intact after rejected reinvestigation
    def t43():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-5")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            assert pr["success"] is True
            # Reinvestigation is blocked
            sdk_client.update_session(sid, supersede_stale_approval=True, evidence_snapshot={"x": 1})
            # Approval is fully intact
            sess = sdk_client.get_session(sid)
            ap = sess["approval_state"]
            assert ap["action_id"] == aid
            assert ap["status"] == "pending"
            assert ap.get("decision_in_progress") is not None
            # Decision can still be completed
            token = pr["token"]
            cr = sdk_client.complete_decision(sid, aid, token)
            assert cr["success"] is True
            assert cr["status"] == "approved"
    check("test_pending_approval_survives_rejected_reinvestigation", t43)

    # 44: Normal reinvestigation still works when no approval is active
    def t44():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-6", evidence_snapshot={"old": True})
            sid = s["id"]
            ur = sdk_client.update_session(
                sid, supersede_stale_approval=True,
                evidence_snapshot={"new": True}
            )
            assert ur["success"] is True
            sess = sdk_client.get_session(sid)
            assert sess["evidence_snapshot"] == {"new": True}
            assert sess["approval_state"] is None
    check("test_normal_reinvestigation_no_active_approval", t44)

    # 45: Normal approval flow still works end-to-end
    def t45():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-7")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            assert pr["success"] is True
            cr = sdk_client.complete_decision(sid, aid, pr["token"])
            assert cr["success"] is True
            assert cr["status"] == "approved"
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["status"] == "approved"
    check("test_normal_approval_flow_e2e", t45)

    # 46: Failed TrueForge forwarding remains retryable
    def t46():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-8")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            assert pr["success"] is True
            # TrueForge forwarding fails
            fr = sdk_client.fail_decision(sid, aid, pr["token"], "network timeout")
            assert fr["success"] is True
            assert fr["retryable"] is True
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["status"] == "pending"
            assert sess["approval_state"].get("forward_error") == "network timeout"
    check("test_failed_forwarding_remains_retryable", t46)

    # 47: Duplicate live approval requests blocked
    def t47():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RACE-9")
            sid = s["id"]
            r1 = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r1["success"] is True
            # Second request with same incident_id while first is pending
            r2 = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r2["success"] is False, "Second request must be blocked"
            # Second request with different incident_id
            r3 = sdk_client.request_approval(sid, "ISOLATE_HOST", {"incident_id": "OTHER"})
            assert r3["success"] is False, "Different incident_id request must also be blocked"
    check("test_duplicate_live_requests_blocked", t47)

    # 48: _has_active_approval_operation helper correctness
    def t48():
        from app.sdk_client import _has_active_approval_operation, REQUEST_CLAIM_TIMEOUT_SECONDS
        from datetime import datetime, timezone, timedelta
        # No approval state
        assert _has_active_approval_operation({}) is None
        assert _has_active_approval_operation({"approval_state": None}) is None
        # Terminal status
        assert _has_active_approval_operation({
            "approval_state": {"status": "approved", "action_id": "a"}
        }) is None
        assert _has_active_approval_operation({
            "approval_state": {"status": "superseded", "action_id": "a"}
        }) is None
        # Pending with no active operation
        assert _has_active_approval_operation({
            "approval_state": {"status": "pending", "action_id": "a"}
        }) is None
        # Pending with decision_in_progress
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "decision_in_progress": {"decision": "approved", "token": "t"}
            }
        }) is not None
        # Pending with request_in_flight but NO timestamp (backwards compat) → expired
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True
            }
        }) is None, "request_in_flight without timestamp should be treated as expired"
        # Pending with request_in_flight + fresh timestamp → active
        now_iso = datetime.now(timezone.utc).isoformat()
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": now_iso,
            }
        }) is not None, "Fresh request_in_flight must block"
        # Pending with request_in_flight + expired timestamp → expired
        old_time = (datetime.now(timezone.utc) - timedelta(seconds=REQUEST_CLAIM_TIMEOUT_SECONDS + 60)).isoformat()
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": old_time,
            }
        }) is None, "Expired request_in_flight must not block"
        # Pending with request_in_flight + invalid timestamp → treated as expired
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": "not-a-date",
            }
        }) is None, "Invalid timestamp must be treated as expired"
        # Pending with both decision_in_progress and request_in_flight active
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "decision_in_progress": {"decision": "approved"},
                "request_in_flight": True,
                "request_started_at": now_iso,
            }
        }) is not None
    check("test_has_active_approval_operation", t48)

    # ------------------------------------------------------------------
    # 49-58: Bug 1 (late-forward) + Bug 2 (lease) regression tests
    # ------------------------------------------------------------------

    # 49: Superseded action rejects late tool_call_id
    def t49():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LF-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.update_session(sid, supersede_stale_approval=True, evidence_snapshot={"x": 1})
            br = sdk_client.set_approval_tool_call_id(sid, aid, "late-tc")
            assert br["success"] is False
            assert "superseded" in br["error"]
    check("test_superseded_rejects_late_tool_call_id", t49)

    # 50: Approved action can receive late tool_call_id
    def t50():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LF-2")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "late-approved-tc")
            assert br["success"] is True
            assert br.get("pending_decision") == "approved"
    check("test_approved_allows_late_tool_call_id", t50)

    # 51: Rejected action can receive late tool_call_id
    def t51():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LF-3")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.reject_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "late-rejected-tc")
            assert br["success"] is True
            assert br.get("pending_decision") == "rejected"
    check("test_rejected_allows_late_tool_call_id", t51)

    # 52: Late approved decision forwarded exactly once
    def t52():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LF-4")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br1 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-1")
            assert br1.get("pending_decision") == "approved"
            assert br1.get("already_forwarded") is not True
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-1")
            assert br2.get("already_forwarded") is True
    check("test_late_approved_forwarded_exactly_once", t52)

    # 53: Late rejected decision forwarded exactly once
    def t53():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LF-5")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.reject_action(sid, aid)
            br1 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-2")
            assert br1.get("pending_decision") == "rejected"
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-2")
            assert br2.get("already_forwarded") is True
    check("test_late_rejected_forwarded_exactly_once", t53)

    # 54: Normal pending binding still works
    def t54():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LF-6")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "normal-tc")
            assert br["success"] is True
            assert "pending_decision" not in br
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["tool_call_id"] == "normal-tc"
    check("test_normal_pending_binding", t54)

    # 55: Fresh request_in_flight blocks duplicate request
    def t55():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LS-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r["success"] is True
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"].get("request_started_at") is not None
            # Duplicate blocked
            r2 = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r2["success"] is False
            assert r2.get("in_flight") is True
    check("test_fresh_request_in_flight_blocks_duplicate", t55)

    # 56: Fresh request_in_flight blocks reinvestigation
    def t56():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LS-2")
            sid = s["id"]
            sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            ur = sdk_client.update_session(
                sid, supersede_stale_approval=True,
                evidence_snapshot={"new": True}
            )
            assert ur["success"] is False
            assert ur.get("approval_in_progress") is True
    check("test_fresh_request_blocks_reinvestigation", t56)

    # 57: Expired request_in_flight can be reclaimed
    def t57():
        from datetime import datetime, timezone, timedelta
        from app.sdk_client import REQUEST_CLAIM_TIMEOUT_SECONDS
        def body(sdk_client):
            s = sdk_client.create_session("INC-LS-3")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            # Manually age the timestamp past the lease
            old_time = (
                datetime.now(timezone.utc)
                - timedelta(seconds=REQUEST_CLAIM_TIMEOUT_SECONDS + 60)
            ).isoformat()
            sess = sdk_client.get_session(sid)
            sess["approval_state"]["request_started_at"] = old_time
            # Write back via raw mutation (bypasses update_session protected keys)
            def _age(sessions):
                for s2 in sessions:
                    if s2["id"] == sid:
                        s2["approval_state"]["request_started_at"] = old_time
                        for a in s2["actions"]:
                            if a.get("action_id") == aid:
                                a["request_started_at"] = old_time
            sdk_client._mutate_sessions(_age)
            # Now reinvestigation should succeed (claim expired)
            ur = sdk_client.update_session(
                sid, supersede_stale_approval=True,
                evidence_snapshot={"reclaimed": True}
            )
            assert ur["success"] is True, "Expired lease must allow reinvestigation"
            assert ur.get("superseded_action_id") == aid
    check("test_expired_request_can_be_reclaimed", t57)

    # 58: Expired request allows new approval request
    def t58():
        from datetime import datetime, timezone, timedelta
        from app.sdk_client import REQUEST_CLAIM_TIMEOUT_SECONDS
        def body(sdk_client):
            s = sdk_client.create_session("INC-LS-4")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            # Age the timestamp
            old_time = (
                datetime.now(timezone.utc)
                - timedelta(seconds=REQUEST_CLAIM_TIMEOUT_SECONDS + 60)
            ).isoformat()
            def _age(sessions):
                for s2 in sessions:
                    if s2["id"] == sid:
                        s2["approval_state"]["request_started_at"] = old_time
                        for a in s2["actions"]:
                            if a.get("action_id") == aid:
                                a["request_started_at"] = old_time
            sdk_client._mutate_sessions(_age)
            # Supersede the expired approval first
            sdk_client.update_session(sid, supersede_stale_approval=True, evidence_snapshot={"x": 1})
            # Now a fresh request should succeed
            r2 = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r2["success"] is True
            assert r2.get("reused") is False
    check("test_expired_request_allows_new_approval", t58)

    # 59: Successful request clears request_in_flight and timestamp
    def t59():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LS-5")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            # Simulate successful TrueForge response
            br = sdk_client.set_approval_tool_call_id(sid, aid, "success-tc")
            assert br["success"] is True
            sess = sdk_client.get_session(sid)
            ap = sess["approval_state"]
            assert ap["request_in_flight"] is False
            assert ap.get("request_started_at") is None
            assert ap["tool_call_id"] == "success-tc"
    check("test_successful_request_clears_timestamp", t59)

    # 60: Failed request clears request_in_flight and timestamp
    def t60():
        def body(sdk_client):
            s = sdk_client.create_session("INC-LS-6")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            # Simulate failed TrueForge response
            sdk_client.release_request_claim(sid, aid)
            sess = sdk_client.get_session(sid)
            ap = sess["approval_state"]
            assert ap["request_in_flight"] is False
            assert ap.get("request_started_at") is None
    check("test_failed_request_clears_timestamp", t60)

    # ------------------------------------------------------------------
    # 61-68: Bug 1 regression — forwarding state recovery
    # ------------------------------------------------------------------

    # 61: Approved action enters forwarding state (forwarding_to_trueforge)
    def t61():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            # set_approval_tool_call_id enters forwarding state
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-1")
            assert br["success"] is True
            assert br.get("pending_decision") == "approved"
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarding_to_trueforge") is True
            assert act.get("forwarded_to_trueforge") is not True
    check("test_approved_enters_forwarding_state", t61)

    # 62: Crash/failure before TrueForge confirmation leaves it recoverable
    def t62():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-2")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-2")
            assert br.get("pending_decision") == "approved"
            # Simulate crash: release forwarding claim (TrueForge failed)
            sdk_client.release_forwarding_claim(sid, aid, "crash")
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarding_to_trueforge") is False
            assert act.get("forwarded_to_trueforge") is False
            # Decision is still retryable
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-2")
            assert br2.get("pending_decision") == "approved"
    check("test_crash_before_confirmation_is_recoverable", t62)

    # 63: Retry successfully forwards the decision
    def t63():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-3")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            # First attempt: forwarding state
            sdk_client.set_approval_tool_call_id(sid, aid, "tc-3")
            sdk_client.release_forwarding_claim(sid, aid, "timeout")
            # Retry: enters forwarding state again
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-3")
            assert br.get("pending_decision") == "approved"
            # Complete the forwarding
            sdk_client.complete_forwarding(sid, aid)
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
            assert act.get("forwarding_to_trueforge") is False
    check("test_retry_successfully_forwards", t63)

    # 64: Successful forwarding becomes terminal forwarded state
    def t64():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-4")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            sdk_client.set_approval_tool_call_id(sid, aid, "tc-4")
            sdk_client.complete_forwarding(sid, aid)
            # Now it shows as already forwarded
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-4")
            assert br.get("already_forwarded") is True
            assert "pending_decision" not in br
    check("test_successful_forwarding_is_terminal", t64)

    # 65: Repeated forwarding does not duplicate the decision
    def t65():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-5")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            sdk_client.set_approval_tool_call_id(sid, aid, "tc-5")
            sdk_client.complete_forwarding(sid, aid)
            # Second call sees already forwarded
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-5")
            assert br.get("already_forwarded") is True
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-5")
            assert br2.get("already_forwarded") is True
    check("test_repeated_forwarding_no_duplicate", t65)

    # 66: Rejected actions have same recovery behavior
    def t66():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-6")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.reject_action(sid, aid)
            # Enter forwarding state
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-6")
            assert br.get("pending_decision") == "rejected"
            # Crash: release and retry
            sdk_client.release_forwarding_claim(sid, aid, "crash")
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-6")
            assert br2.get("pending_decision") == "rejected"
            # Complete
            sdk_client.complete_forwarding(sid, aid)
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
    check("test_rejected_recovery_same_as_approved", t66)

    # 67: Superseded actions remain rejected
    def t67():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-7")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.update_session(sid, supersede_stale_approval=True, evidence_snapshot={"x": 1})
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-7")
            assert br["success"] is False
            assert "superseded" in br["error"]
    check("test_superseded_still_rejected", t67)

    # 68: Normal pending approval flow still works
    def t68():
        def body(sdk_client):
            s = sdk_client.create_session("INC-FWD-8")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-8")
            assert br["success"] is True
            assert "pending_decision" not in br
            sess = sdk_client.get_session(sid)
            ap = sess["approval_state"]
            assert ap["tool_call_id"] == "tc-8"
            assert ap["status"] == "pending"
    check("test_normal_pending_flow_intact", t68)

    # ------------------------------------------------------------------
    # 69-74: Bug 2 regression — malformed request_started_at
    # ------------------------------------------------------------------

    # 69: integer request_started_at treated as expired
    def t69():
        from app.sdk_client import _has_active_approval_operation
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": 123,
            }
        }) is None, "Integer timestamp must be treated as expired"
    check("test_malformed_timestamp_integer", t69)

    # 70: dict request_started_at treated as expired
    def t70():
        from app.sdk_client import _has_active_approval_operation
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": {"ts": "now"},
            }
        }) is None, "Dict timestamp must be treated as expired"
    check("test_malformed_timestamp_dict", t70)

    # 71: list request_started_at treated as expired
    def t71():
        from app.sdk_client import _has_active_approval_operation
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": ["2026"],
            }
        }) is None, "List timestamp must be treated as expired"
    check("test_malformed_timestamp_list", t71)

    # 72: malformed string treated as expired
    def t72():
        from app.sdk_client import _has_active_approval_operation
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": "not-a-date",
            }
        }) is None, "Malformed string must be treated as expired"
    check("test_malformed_timestamp_string", t72)

    # 73: valid fresh timestamp blocks
    def t73():
        from app.sdk_client import _has_active_approval_operation
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": now_iso,
            }
        }) is not None, "Fresh timestamp must block"
    check("test_valid_fresh_timestamp_blocks", t73)

    # 74: valid expired timestamp does not block
    def t74():
        from app.sdk_client import _has_active_approval_operation, REQUEST_CLAIM_TIMEOUT_SECONDS
        from datetime import datetime, timezone, timedelta
        old_time = (
            datetime.now(timezone.utc)
            - timedelta(seconds=REQUEST_CLAIM_TIMEOUT_SECONDS + 60)
        ).isoformat()
        assert _has_active_approval_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": old_time,
            }
        }) is None, "Expired timestamp must not block"
    check("test_valid_expired_timestamp_does_not_block", t74)

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("Failures:")
        for e in errors:
            print(f"  - {e}")
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)

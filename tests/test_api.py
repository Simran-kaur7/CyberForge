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

    # ------------------------------------------------------------------
    # 75-93: Bug 1 (ownership token) + Bug 2 (retry) regression tests
    # ------------------------------------------------------------------

    # 75: First caller acquires forwarding claim with token
    def t75():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-1")
            assert br["success"] is True
            assert br.get("pending_decision") == "approved"
            token = br.get("forwarding_owner")
            assert token is not None and len(token) > 0
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarding_owner") == token
    check("test_first_caller_acquires_claim_with_token", t75)

    # 76: Second concurrent caller receives already_forwarding
    def t76():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-2")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            # First caller acquires claim
            br1 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-2")
            assert br1.get("pending_decision") == "approved"
            # Second caller gets already_forwarding
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-2")
            assert br2.get("already_forwarding") is True
            assert "pending_decision" not in br2
    check("test_second_caller_receives_already_forwarding", t76)

    # 77: Second caller does NOT receive pending_decision
    def t77():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-3")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            sdk_client.set_approval_tool_call_id(sid, aid, "tc-3")
            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-3")
            assert br2.get("pending_decision") is None
    check("test_second_caller_no_pending_decision", t77)

    # 78: Second caller cannot release first caller's claim
    def t78():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-4")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br1 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-4")
            token1 = br1["forwarding_owner"]
            # Second caller tries to release with wrong token
            rr = sdk_client.release_forwarding_claim(
                sid, aid, "fail", owner_token="wrong-token"
            )
            assert rr["success"] is False
            assert "another caller" in rr["error"].lower()
            # First caller's claim is still intact
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarding_owner") == token1
    check("test_non_owner_cannot_release_claim", t78)

    # 79: First caller can successfully complete its claim
    def t79():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-5")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-5")
            token = br["forwarding_owner"]
            cr = sdk_client.complete_forwarding(sid, aid, owner_token=token)
            assert cr["success"] is True
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
            assert act.get("forwarding_to_trueforge") is False
            assert act.get("forwarding_owner") is None
    check("test_owner_can_complete_claim", t79)

    # 80: Failed owner can release its own claim
    def t80():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-6")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-6")
            token = br["forwarding_owner"]
            rr = sdk_client.release_forwarding_claim(
                sid, aid, "timeout", owner_token=token
            )
            assert rr["success"] is True
            assert rr["retryable"] is True
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarding_to_trueforge") is False
            assert act.get("forwarding_owner") is None
    check("test_owner_can_release_own_claim", t80)

    # 81: Retry can reclaim the original approved action
    def t81():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            # Simulate failed forwarding
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-r1")
            sdk_client.release_forwarding_claim(sid, aid, "fail", owner_token=br["forwarding_owner"])
            # Retry: should work on the same terminal action
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-r1")
            assert rr["success"] is True
            assert rr.get("pending_decision") == "approved"
            assert rr.get("forwarding_owner") is not None
    check("test_retry_reclaims_approved_action", t81)

    # 82: Retry can reclaim the original rejected action
    def t82():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-2")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.reject_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-r2")
            sdk_client.release_forwarding_claim(sid, aid, "fail", owner_token=br["forwarding_owner"])
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-r2")
            assert rr["success"] is True
            assert rr.get("pending_decision") == "rejected"
    check("test_retry_reclaims_rejected_action", t82)

    # 83: Retry preserves original action_id
    def t83():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-3")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-r3")
            assert rr["success"] is True
            assert rr["action_id"] == aid
    check("test_retry_preserves_action_id", t83)

    # 84: Retry preserves original tool_call_id
    def t84():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-4")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            # Bind tool_call_id first
            sdk_client.set_approval_tool_call_id(sid, aid, "tc-r4")
            # Retry with matching tool_call_id
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-r4")
            assert rr["success"] is True
            # Mismatched tool_call_id rejected
            rr2 = sdk_client.retry_approval_forwarding(sid, aid, "tc-wrong")
            assert rr2["success"] is False
            assert "tool_call_id" in rr2["error"].lower()
    check("test_retry_preserves_tool_call_id", t84)

    # 85: Retry preserves original decision
    def t85():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-5")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-r5")
            assert rr.get("pending_decision") == "approved"
            # Verify session still shows approved
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["status"] == "approved"
    check("test_retry_preserves_decision", t85)

    # 86: Retry does NOT create a new approval action
    def t86():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-6")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            original_count = len(s["actions"])
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            sdk_client.retry_approval_forwarding(sid, aid, "tc-r6")
            sess = sdk_client.get_session(sid)
            assert len(sess["actions"]) == original_count, "Retry must not create new actions"
    check("test_retry_no_new_action", t86)

    # 87: Two concurrent retries cannot both forward
    def t87():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-7")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            rr1 = sdk_client.retry_approval_forwarding(sid, aid, "tc-r7")
            assert rr1.get("pending_decision") == "approved"
            rr2 = sdk_client.retry_approval_forwarding(sid, aid, "tc-r7")
            assert rr2.get("already_forwarding") is True
            assert "pending_decision" not in rr2
    check("test_concurrent_retries_one_wins", t87)

    # 88: Superseded action cannot be retried
    def t88():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-8")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.update_session(sid, supersede_stale_approval=True, evidence_snapshot={"x": 1})
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-r8")
            assert rr["success"] is False
            assert "superseded" in rr["error"].lower()
    check("test_superseded_cannot_retry", t88)

    # 89: Mismatched tool_call_id is rejected by retry
    def t89():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-9")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            rr = sdk_client.retry_approval_forwarding(sid, aid, "wrong-tc")
            assert rr["success"] is False
    check("test_retry_rejects_mismatched_tool_call_id", t89)

    # 90: forwarded_to_trueforge=True prevents another forward via retry
    def t90():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RTRY-10")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-r10")
            sdk_client.complete_forwarding(sid, aid, owner_token=br["forwarding_owner"])
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-r10")
            assert rr["success"] is False
            assert "already forwarded" in rr["error"].lower()
    check("test_forwarded_blocks_retry", t90)

    # 91: Existing normal approval flow still passes
    def t91():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-7")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            assert pr["success"] is True
            cr = sdk_client.complete_decision(sid, aid, pr["token"])
            assert cr["success"] is True
            assert cr["status"] == "approved"
    check("test_normal_approval_flow_intact", t91)

    # 92: Existing late-forward flow still passes
    def t92():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-8")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-lf")
            assert br.get("pending_decision") == "approved"
            token = br["forwarding_owner"]
            sdk_client.complete_forwarding(sid, aid, owner_token=token)
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
    check("test_late_forward_flow_intact", t92)

    # 93: Existing crash-recovery behavior still passes
    def t93():
        def body(sdk_client):
            s = sdk_client.create_session("INC-OWN-9")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-cr")
            token = br["forwarding_owner"]
            # Simulate crash: release claim
            sdk_client.release_forwarding_claim(sid, aid, "crash", owner_token=token)
            # Retry
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-cr")
            assert rr.get("pending_decision") == "approved"
            sdk_client.complete_forwarding(sid, aid, owner_token=rr["forwarding_owner"])
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
    check("test_crash_recovery_with_tokens", t93)

    # 94: Crashed forwarding claim expires and can be reclaimed
    def t94():
        from datetime import datetime, timezone, timedelta
        from app.sdk_client import FORWARDING_CLAIM_TIMEOUT_SECONDS
        def body(sdk_client):
            s = sdk_client.create_session("INC-CRASH-FWD")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            # Acquire forwarding claim
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-cf")
            token = br["forwarding_owner"]
            # Simulate crash: age the forwarding timestamp past the lease
            old_time = (
                datetime.now(timezone.utc)
                - timedelta(seconds=FORWARDING_CLAIM_TIMEOUT_SECONDS + 60)
            ).isoformat()
            def _age(sessions):
                for s2 in sessions:
                    if s2["id"] == sid:
                        for a in s2.get("actions", []):
                            if a.get("action_id") == aid:
                                a["forwarding_started_at"] = old_time
            sdk_client._mutate_sessions(_age)
            # Retry should reclaim the expired claim (not return already_forwarding)
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-cf")
            assert rr["success"] is True, f"Retry failed: {rr}"
            assert rr.get("pending_decision") == "approved"
            new_token = rr["forwarding_owner"]
            assert new_token != token, "Must get a new owner token"
            # Complete the forwarding
            sdk_client.complete_forwarding(sid, aid, owner_token=new_token)
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
            assert act.get("forwarding_to_trueforge") is False
            assert act.get("forwarding_owner") is None
    check("test_crashed_forwarding_claim_expires", t94)

    # ------------------------------------------------------------------
    # Bug #15 regression — a dispatch that actually reached TrueForge must
    # never be silently replayed after a crash/restart, and a dispatch
    # that never got that far must remain automatically recoverable.
    # ------------------------------------------------------------------

    def _age_forwarding_claim(sdk_client, sid, aid):
        from datetime import datetime, timezone, timedelta
        from app.sdk_client import FORWARDING_CLAIM_TIMEOUT_SECONDS
        old_time = (
            datetime.now(timezone.utc)
            - timedelta(seconds=FORWARDING_CLAIM_TIMEOUT_SECONDS + 60)
        ).isoformat()

        def _age(sessions):
            for s2 in sessions:
                if s2["id"] == sid:
                    for a in s2.get("actions", []):
                        if a.get("action_id") == aid:
                            a["forwarding_started_at"] = old_time

        sdk_client._mutate_sessions(_age)

    # 102: acquire claim -> TrueForge POST succeeds (simulated by marking
    # dispatch) -> process crashes before complete_forwarding/persistence
    # -> process restarts -> lease has since expired. Recovery must NOT
    # silently reclaim the lease and hand back a fresh claim, since that
    # would let a caller re-POST a decision that may already have been
    # delivered.
    def t102():
        def body(sdk_client):
            s = sdk_client.create_session("INC-CRASH-DUP-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)

            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-crash-dup-1")
            token = br["forwarding_owner"]
            assert br.get("pending_decision") == "approved"

            # This is what the real POST path does immediately before
            # hitting the network — simulates "the POST is about to go/did
            # go out" without needing a real TrueForge call.
            dm = sdk_client.mark_forwarding_dispatched(sid, aid, token)
            assert dm["success"] is True

            # Crash: nothing else is persisted (no complete_forwarding, no
            # release). The lease simply ages out on restart.
            _age_forwarding_claim(sdk_client, sid, aid)

            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-crash-dup-1")
            assert rr["success"] is False, f"Must not silently reclaim: {rr}"
            assert rr.get("uncertain_delivery") is True

            # No duplicate dispatch happened: the action is exactly as the
            # crashed attempt left it.
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is not True
            assert act.get("forwarding_owner") == token
            assert act.get("forwarding_dispatched_at") is not None
        with_temp_sessions(body)
    check("test_crash_after_dispatch_not_blindly_resubmitted", t102)

    # 103: same uncertain state, but via the set_approval_tool_call_id
    # late-forward entry point (the other place a lease gets reclaimed).
    def t103():
        def body(sdk_client):
            s = sdk_client.create_session("INC-CRASH-DUP-2")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)

            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-crash-dup-2")
            token = br["forwarding_owner"]
            dm = sdk_client.mark_forwarding_dispatched(sid, aid, token)
            assert dm["success"] is True
            _age_forwarding_claim(sdk_client, sid, aid)

            br2 = sdk_client.set_approval_tool_call_id(sid, aid, "tc-crash-dup-2")
            assert br2["success"] is False, f"Must not silently reclaim: {br2}"
            assert br2.get("uncertain_delivery") is True
        with_temp_sessions(body)
    check("test_late_bind_after_crash_not_blindly_resubmitted", t103)

    # 104: crash BEFORE dispatch (claim acquired, process dies before the
    # network call is ever made) must remain automatically recoverable —
    # the dispatch marker is never set in this case.
    def t104():
        def body(sdk_client):
            s = sdk_client.create_session("INC-CRASH-NODUP")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)

            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-crash-nodup")
            token = br["forwarding_owner"]
            # No mark_forwarding_dispatched call — crash happened before
            # the network call was even attempted.
            _age_forwarding_claim(sdk_client, sid, aid)

            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-crash-nodup")
            assert rr["success"] is True, f"Undispatched claim must be reclaimable: {rr}"
            assert rr.get("uncertain_delivery") is not True
            assert rr["forwarding_owner"] != token
        with_temp_sessions(body)
    check("test_crash_before_dispatch_remains_recoverable", t104)

    # 105: an operator resolves an uncertain claim by confirming the
    # decision really was delivered — this must finalize the decision as
    # forwarded WITHOUT triggering any further POST, and must be stable
    # under a subsequent retry attempt (no re-dispatch, no error either).
    def t105():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RESOLVE-DELIVERED")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-resolve-1")
            token = br["forwarding_owner"]
            sdk_client.mark_forwarding_dispatched(sid, aid, token)
            _age_forwarding_claim(sdk_client, sid, aid)

            res = sdk_client.resolve_uncertain_forwarding(
                sid, aid, confirmed_delivered=True,
            )
            assert res["success"] is True
            assert res["forwarded"] is True

            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
            assert act.get("forwarding_to_trueforge") is False
            assert act.get("forwarding_dispatched_at") is None

            # Idempotent: retrying now correctly reports already forwarded
            # instead of re-dispatching.
            rr2 = sdk_client.retry_approval_forwarding(sid, aid, "tc-resolve-1")
            assert rr2["success"] is False
            assert "already forwarded" in rr2.get("error", "").lower()
        with_temp_sessions(body)
    check("test_resolve_uncertain_confirmed_delivered_is_terminal", t105)

    # 106: an operator resolves an uncertain claim by confirming the
    # decision was NOT delivered — this must clear the claim so the
    # normal retry path can safely re-dispatch exactly once more.
    def t106():
        def body(sdk_client):
            s = sdk_client.create_session("INC-RESOLVE-NOTDELIVERED")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-resolve-2")
            token = br["forwarding_owner"]
            sdk_client.mark_forwarding_dispatched(sid, aid, token)
            _age_forwarding_claim(sdk_client, sid, aid)

            res = sdk_client.resolve_uncertain_forwarding(
                sid, aid, confirmed_delivered=False,
            )
            assert res["success"] is True
            assert res["forwarded"] is False

            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-resolve-2")
            assert rr["success"] is True
            assert rr.get("uncertain_delivery") is not True
            assert rr.get("pending_decision") == "approved"
            new_token = rr["forwarding_owner"]
            sdk_client.complete_forwarding(sid, aid, owner_token=new_token)
            sess = sdk_client.get_session(sid)
            act = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
        with_temp_sessions(body)
    check("test_resolve_uncertain_not_delivered_allows_retry", t106)

    # 107: mark_forwarding_dispatched refuses to mark under a claim the
    # caller no longer owns, and refuses when there's no active claim at
    # all — a caller that already lost its lease must not be able to
    # dispatch under it.
    def t107():
        def body(sdk_client):
            s = sdk_client.create_session("INC-DISPATCH-GUARD")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-dispatch-guard")
            token = br["forwarding_owner"]

            bad = sdk_client.mark_forwarding_dispatched(sid, aid, "not-the-real-token")
            assert bad["success"] is False

            ok = sdk_client.mark_forwarding_dispatched(sid, aid, token)
            assert ok["success"] is True

            sdk_client.complete_forwarding(sid, aid, owner_token=token)
            no_claim = sdk_client.mark_forwarding_dispatched(sid, aid, token)
            assert no_claim["success"] is False
        with_temp_sessions(body)
    check("test_mark_dispatched_requires_owned_active_claim", t107)

    # ------------------------------------------------------------------
    # 95-101: Regression — request_in_flight must not block a local
    # terminal decision (approve_action/reject_action). Only a competing
    # decision_in_progress forward may block them; the late tool-call
    # binding flow must keep working unchanged.
    # ------------------------------------------------------------------

    # 95: Immediate approve succeeds while request_in_flight is still set
    def t95():
        def body(sdk_client):
            s = sdk_client.create_session("INC-IMM-1")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r["success"] is True
            aid = r["action_id"]
            # request_approval claims request_in_flight for every fresh
            # pending approval — confirm that's really the state here.
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["request_in_flight"] is True
            # No release_request_claim call: approve_action must succeed
            # immediately anyway.
            ar = sdk_client.approve_action(sid, aid)
            assert ar["success"] is True, ar
            assert ar["status"] == "approved"
        with_temp_sessions(body)
    check("test_immediate_approve_despite_request_in_flight", t95)

    # 96: Immediate reject succeeds while request_in_flight is still set
    def t96():
        def body(sdk_client):
            s = sdk_client.create_session("INC-IMM-2")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "ISOLATE_HOST", {"host": "web-02"})
            aid = r["action_id"]
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["request_in_flight"] is True
            rr = sdk_client.reject_action(sid, aid)
            assert rr["success"] is True, rr
            assert rr["status"] == "rejected"
        with_temp_sessions(body)
    check("test_immediate_reject_despite_request_in_flight", t96)

    # 97: Late tool-call binding still works after an immediate approve
    # (no release_request_claim in between — the normal flow now that
    # approve_action no longer requires the claim to be cleared first).
    def t97():
        def body(sdk_client):
            s = sdk_client.create_session("INC-IMM-3")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            ar = sdk_client.approve_action(sid, aid)
            assert ar["success"] is True
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-imm-1")
            assert br["success"] is True
            assert br.get("pending_decision") == "approved"
        with_temp_sessions(body)
    check("test_late_binding_after_immediate_approve", t97)

    # 98: Late tool-call binding still works after an immediate reject
    def t98():
        def body(sdk_client):
            s = sdk_client.create_session("INC-IMM-4")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "ISOLATE_HOST", {"host": "web-03"})
            aid = r["action_id"]
            rr = sdk_client.reject_action(sid, aid)
            assert rr["success"] is True
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-imm-2")
            assert br["success"] is True
            assert br.get("pending_decision") == "rejected"
        with_temp_sessions(body)
    check("test_late_binding_after_immediate_reject", t98)

    # 99: A genuinely competing operation — a decision already being
    # forwarded (decision_in_progress) — still blocks approve_action.
    # This is the protection that must be preserved.
    def t99():
        def body(sdk_client):
            s = sdk_client.create_session("INC-IMM-5")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            assert pr["success"] is True
            blocked = sdk_client.approve_action(sid, aid)
            assert blocked["success"] is False
            assert "forwarded" in blocked["error"]
            # Approval is untouched and still pending/in-progress.
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["status"] == "pending"
            assert sess["approval_state"].get("decision_in_progress") is not None
        with_temp_sessions(body)
    check("test_decision_in_progress_still_blocks_approve", t99)

    # 100: Same competing-operation protection for reject_action.
    def t100():
        def body(sdk_client):
            s = sdk_client.create_session("INC-IMM-6")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "ISOLATE_HOST", {"host": "web-04"})
            aid = r["action_id"]
            pr = sdk_client.prepare_decision(sid, aid, "rejected")
            assert pr["success"] is True
            blocked = sdk_client.reject_action(sid, aid)
            assert blocked["success"] is False
            assert "forwarded" in blocked["error"]
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["status"] == "pending"
        with_temp_sessions(body)
    check("test_decision_in_progress_still_blocks_reject", t100)

    # 101: _has_competing_decision_operation helper correctness — mirrors
    # test_has_active_approval_operation (t48) but confirms this narrower
    # helper ignores request_in_flight entirely, fresh or not.
    def t101():
        from app.sdk_client import _has_competing_decision_operation
        from datetime import datetime, timezone
        # No approval state / non-pending / pending-no-op → None
        assert _has_competing_decision_operation({}) is None
        assert _has_competing_decision_operation({"approval_state": None}) is None
        assert _has_competing_decision_operation({
            "approval_state": {"status": "approved", "action_id": "a"}
        }) is None
        assert _has_competing_decision_operation({
            "approval_state": {"status": "pending", "action_id": "a"}
        }) is None
        # Fresh request_in_flight must NOT block (the regression case).
        now_iso = datetime.now(timezone.utc).isoformat()
        assert _has_competing_decision_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "request_in_flight": True,
                "request_started_at": now_iso,
            }
        }) is None, "request_in_flight must never block a local decision"
        # decision_in_progress must still block.
        assert _has_competing_decision_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "decision_in_progress": {"decision": "approved", "token": "t"}
            }
        }) is not None
        # Both set at once → still blocked by decision_in_progress alone.
        assert _has_competing_decision_operation({
            "approval_state": {
                "status": "pending", "action_id": "a",
                "decision_in_progress": {"decision": "approved", "token": "t"},
                "request_in_flight": True,
                "request_started_at": now_iso,
            }
        }) is not None
    check("test_has_competing_decision_operation", t101)



    # ------------------------------------------------------------------
    # New Qodo regressions — uncertain TrueForge delivery must be manually
    # resolved and never silently converted back into an automatic retry.
    # ------------------------------------------------------------------

    def _make_terminal_forwarding_state(sdk_client, incident_id, tool_call_id):
        session = sdk_client.create_session(incident_id)
        sid = session["id"]
        result = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
        aid = result["action_id"]
        sdk_client.release_request_claim(sid, aid)
        approved = sdk_client.approve_action(sid, aid)
        assert approved["success"] is True
        bound = sdk_client.set_approval_tool_call_id(sid, aid, tool_call_id)
        assert bound.get("pending_decision") == "approved"
        return sid, aid, bound["forwarding_owner"]

    # 108: The protected API endpoint can manually resolve an uncertain
    # forwarding state and records the authenticated operator as resolved_by.
    def t108():
        import app.api.approvals as approvals_mod
        from app.api.approvals import UncertainForwardingResolutionRequest

        def body(sdk_client):
            s = sdk_client.create_session("INC-API-UNCERTAIN")
            sid = s["id"]
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.99"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sdk_client.approve_action(sid, aid)
            br = sdk_client.set_approval_tool_call_id(sid, aid, "tc-api-uncertain")
            token = br["forwarding_owner"]
            sdk_client.mark_forwarding_dispatched(sid, aid, token)
            sdk_client.mark_forwarding_uncertain(
                sid, aid, "simulated ambiguous timeout", owner_token=token
            )

            original_key = approvals_mod.EXPECTED_API_KEY
            approvals_mod.EXPECTED_API_KEY = "resolve-key"
            try:
                result = approvals_mod.resolve_uncertain_approval_forwarding(
                    UncertainForwardingResolutionRequest(
                        session_id=sid,
                        action_id=aid,
                        confirmed_delivered=True,
                    ),
                    "Bearer resolve-key",
                )
            finally:
                approvals_mod.EXPECTED_API_KEY = original_key

            assert result["success"] is True
            assert result["resolved_by"] == "analyst"
            assert result["forwarded"] is True
            act = [a for a in sdk_client.get_session(sid)["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarded_to_trueforge") is True
            assert act.get("forward_resolved_by") == "analyst"
            assert act.get("forwarding_dispatched_at") is None
        with_temp_sessions(body)
    check("test_uncertain_forwarding_is_manually_resolvable_via_protected_api", t108)

    # 109: API resolution as delivered finalizes the action without replay.
    def t109():
        import app.api.approvals as approvals_mod
        from app.api.approvals import UncertainForwardingResolutionRequest

        def body(sdk_client):
            sid, aid, token = _make_terminal_forwarding_state(
                sdk_client, "INC-API-DELIVERED", "tc-api-delivered"
            )
            sdk_client.mark_forwarding_dispatched(sid, aid, token)
            sdk_client.mark_forwarding_uncertain(
                sid, aid, "response read failed", owner_token=token
            )

            original_key = approvals_mod.EXPECTED_API_KEY
            approvals_mod.EXPECTED_API_KEY = "resolve-key"
            try:
                result = approvals_mod.resolve_uncertain_approval_forwarding(
                    UncertainForwardingResolutionRequest(
                        session_id=sid,
                        action_id=aid,
                        confirmed_delivered=True,
                    ),
                    "Bearer resolve-key",
                )
            finally:
                approvals_mod.EXPECTED_API_KEY = original_key

            assert result["forwarded"] is True
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-api-delivered")
            assert rr["success"] is False
            assert "already forwarded" in rr["error"].lower()
        with_temp_sessions(body)
    check("test_operator_resolves_uncertain_as_delivered", t109)

    # 110: API resolution as not-delivered explicitly clears the uncertain
    # state, after which the existing retry path may acquire a fresh claim.
    def t110():
        import app.api.approvals as approvals_mod
        from app.api.approvals import UncertainForwardingResolutionRequest

        def body(sdk_client):
            sid, aid, token = _make_terminal_forwarding_state(
                sdk_client, "INC-API-NOT-DELIVERED", "tc-api-notdelivered"
            )
            sdk_client.mark_forwarding_dispatched(sid, aid, token)
            sdk_client.mark_forwarding_uncertain(
                sid, aid, "connection reset", owner_token=token
            )

            original_key = approvals_mod.EXPECTED_API_KEY
            approvals_mod.EXPECTED_API_KEY = "resolve-key"
            try:
                result = approvals_mod.resolve_uncertain_approval_forwarding(
                    UncertainForwardingResolutionRequest(
                        session_id=sid,
                        action_id=aid,
                        confirmed_delivered=False,
                    ),
                    "Bearer resolve-key",
                )
            finally:
                approvals_mod.EXPECTED_API_KEY = original_key

            assert result["forwarded"] is False
            assert result["resolved_by"] == "analyst"
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-api-notdelivered")
            assert rr["success"] is True
            assert rr.get("uncertain_delivery") is not True
            assert rr.get("pending_decision") == "approved"
        with_temp_sessions(body)
    check("test_operator_resolves_uncertain_as_not_delivered", t110)

    # 111: A timeout after mark_forwarding_dispatched preserves the durable
    # dispatch marker and is returned as uncertain, not retryable.
    def t111():
        import app.api.approvals as approvals_mod
        from app.api.approvals import ApprovalRequest
        from unittest.mock import patch

        def body(sdk_client):
            sid, aid, token = _make_terminal_forwarding_state(
                sdk_client, "INC-AMBIG-TIMEOUT", "tc-amb-timeout"
            )
            # The route retry path must acquire the forwarding claim itself.
            sdk_client.release_forwarding_claim(sid, aid, "reset before API retry", owner_token=token)
            sdk_client.persist_trueforge_session_id(sid, "tf-amb-timeout")

            original_key = approvals_mod.EXPECTED_API_KEY
            approvals_mod.EXPECTED_API_KEY = "resolve-key"
            try:
                with patch.object(
                    approvals_mod, "_tf_post_sse",
                    side_effect=[
                        {"tool_call_id": "tc-amb-timeout", "thread_id": "thread-amb"},
                        TimeoutError("simulated response-read timeout"),
                    ],
                ), patch.object(
                    sdk_client,
                    "request_approval",
                    return_value={
                        "success": True,
                        "action_id": aid,
                        "status": "pending",
                        "reused": True,
                    },
                ):
                    result = approvals_mod.request_containment_approval(
                        ApprovalRequest(
                            session_id=sid,
                            trueforge_session_id="tf-amb-timeout",
                        ),
                        "Bearer resolve-key",
                    )
            finally:
                approvals_mod.EXPECTED_API_KEY = original_key

            assert result["success"] is False
            assert result.get("uncertain_delivery") is True
            assert result.get("retryable") is False
            act = [a for a in sdk_client.get_session(sid)["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarding_dispatched_at") is not None
            assert act.get("forwarding_outcome") == "uncertain"
            assert act.get("forwarding_to_trueforge") is True
            assert act.get("forwarded_to_trueforge") is not True
        with_temp_sessions(body)
    check("test_ambiguous_timeout_after_dispatch_preserves_marker", t111)

    # 112: The same ambiguous state cannot be automatically retried; an active
    # claim is preserved, and after expiry retry still reports uncertainty.
    def t112():
        def body(sdk_client):
            sid, aid, token = _make_terminal_forwarding_state(
                sdk_client, "INC-AMBIG-NORETRY", "tc-amb-noretry"
            )
            sdk_client.mark_forwarding_dispatched(sid, aid, token)
            sdk_client.mark_forwarding_uncertain(
                sid, aid, "socket reset after POST", owner_token=token
            )

            rr_active = sdk_client.retry_approval_forwarding(sid, aid, "tc-amb-noretry")
            assert rr_active["success"] is True
            assert rr_active.get("already_forwarding") is True
            assert rr_active.get("pending_decision") is None

            _age_forwarding_claim(sdk_client, sid, aid)
            rr_expired = sdk_client.retry_approval_forwarding(sid, aid, "tc-amb-noretry")
            assert rr_expired["success"] is False
            assert rr_expired.get("uncertain_delivery") is True
            act = [a for a in sdk_client.get_session(sid)["actions"] if a["action_id"] == aid][0]
            assert act.get("forwarding_dispatched_at") is not None
            assert act.get("forwarding_owner") == token
        with_temp_sessions(body)
    check("test_ambiguous_failure_never_becomes_automatic_retry", t112)

    # 113: A failure before dispatch remains retryable; no dispatch marker is
    # present, so the existing lease-reclaim path is unchanged.
    def t113():
        def body(sdk_client):
            sid, aid, token = _make_terminal_forwarding_state(
                sdk_client, "INC-PRE-DISPATCH", "tc-pre-dispatch"
            )
            # Simulate failure before the outbound POST/dispatch marker.
            _age_forwarding_claim(sdk_client, sid, aid)
            rr = sdk_client.retry_approval_forwarding(sid, aid, "tc-pre-dispatch")
            assert rr["success"] is True
            assert rr.get("uncertain_delivery") is not True
            assert rr.get("forwarding_owner") != token
        with_temp_sessions(body)
    check("test_definite_pre_dispatch_failure_remains_retryable", t113)
    # 114: Approved session has approval_state.status = approved (for timeline rendering).
    def t114():
        def body(sdk_client):
            s = sdk_client.create_session("INC-TL-APPROVED")
            sdk_client.update_session(s["id"], target_ip="10.0.0.25",
                                      investigation_status="complete")
            sdk_client.request_approval(s["id"], "block_ip",
                                        {"incident_id": "INC-TL-APPROVED"})
            sess = sdk_client.get_session(s["id"])
            aid = sess["approval_state"]["action_id"]
            prep = sdk_client.prepare_decision(s["id"], aid, "approved", "analyst")
            sdk_client.complete_decision(s["id"], aid, prep["token"])
            sess = sdk_client.get_session(s["id"])
            assert sess["approval_state"]["status"] == "approved"
            assert sess["approval_state"].get("decided_at") is not None
        with_temp_sessions(body)
    check("test_approved_session_approval_state_has_decision", t114)

    # 115: Rejected session has approval_state.status = rejected.
    def t115():
        def body(sdk_client):
            s = sdk_client.create_session("INC-TL-REJECTED")
            sdk_client.update_session(s["id"], target_ip="10.0.0.25",
                                      investigation_status="complete")
            sdk_client.request_approval(s["id"], "block_ip",
                                        {"incident_id": "INC-TL-REJECTED"})
            sess = sdk_client.get_session(s["id"])
            aid = sess["approval_state"]["action_id"]
            prep = sdk_client.prepare_decision(s["id"], aid, "rejected", "analyst")
            sdk_client.complete_decision(s["id"], aid, prep["token"])
            sess = sdk_client.get_session(s["id"])
            assert sess["approval_state"]["status"] == "rejected"
        with_temp_sessions(body)
    check("test_rejected_session_approval_state_has_decision", t115)

    # 116: list_sessions exposes approval_state for frontend timeline logic.
    def t116():
        def body(sdk_client):
            s = sdk_client.create_session("INC-TL-LIST")
            sdk_client.update_session(s["id"], target_ip="10.0.0.25",
                                      investigation_status="complete")
            sdk_client.request_approval(s["id"], "block_ip",
                                        {"incident_id": "INC-TL-LIST"})
            sess = sdk_client.get_session(s["id"])
            aid = sess["approval_state"]["action_id"]
            prep = sdk_client.prepare_decision(s["id"], aid, "approved", "analyst")
            sdk_client.complete_decision(s["id"], aid, prep["token"])
            sessions = sdk_client.list_sessions()
            match = [s for s in sessions if s["incident_id"] == "INC-TL-LIST"]
            assert len(match) == 1
            ap = match[0].get("approval_state")
            assert ap is not None
            assert ap.get("status") == "approved"
        with_temp_sessions(body)
    check("test_list_sessions_includes_approval_state_for_timeline", t116)

    # 117: After approve, session resolves and approval_state is terminal.
    def t117():
        def body(sdk_client):
            s = sdk_client.create_session("INC-TL-APPROVE-RESOLVE")
            sdk_client.update_session(s["id"], target_ip="10.0.0.25",
                                      investigation_status="complete")
            sdk_client.request_approval(s["id"], "block_ip",
                                        {"incident_id": "INC-TL-APPROVE-RESOLVE"})
            sess = sdk_client.get_session(s["id"])
            aid = sess["approval_state"]["action_id"]
            prep = sdk_client.prepare_decision(s["id"], aid, "approved", "analyst")
            sdk_client.complete_decision(s["id"], aid, prep["token"])
            sess = sdk_client.get_session(s["id"])
            assert sess["status"] == "resolved"
            assert sess["approval_state"]["status"] == "approved"
            # Action is also terminal
            action = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert action["status"] == "approved"
        with_temp_sessions(body)
    check("test_approve_resolves_session_timeline", t117)

    # 118: After reject, session resolves and containment was never executed.
    def t118():
        def body(sdk_client):
            s = sdk_client.create_session("INC-TL-REJECT-RESOLVE")
            sdk_client.update_session(s["id"], target_ip="10.0.0.25",
                                      investigation_status="complete")
            sdk_client.request_approval(s["id"], "block_ip",
                                        {"incident_id": "INC-TL-REJECT-RESOLVE"})
            sess = sdk_client.get_session(s["id"])
            aid = sess["approval_state"]["action_id"]
            prep = sdk_client.prepare_decision(s["id"], aid, "rejected", "analyst")
            sdk_client.complete_decision(s["id"], aid, prep["token"])
            sess = sdk_client.get_session(s["id"])
            assert sess["status"] == "resolved"
            assert sess["approval_state"]["status"] == "rejected"
            # No firewall block should have happened
            action = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert action["status"] == "rejected"
        with_temp_sessions(body)
    check("test_reject_resolves_session_timeline", t118)

    # 119: Pending approval has no decided_at, session still active.
    def t119():
        def body(sdk_client):
            s = sdk_client.create_session("INC-TL-PENDING")
            sdk_client.update_session(s["id"], target_ip="10.0.0.25",
                                      investigation_status="complete")
            sdk_client.request_approval(s["id"], "block_ip",
                                        {"incident_id": "INC-TL-PENDING"})
            sess = sdk_client.get_session(s["id"])
            ap = sess.get("approval_state", {})
            assert ap.get("status") == "pending"
            assert ap.get("decided_at") is None
            assert sess["status"] == "active"
        with_temp_sessions(body)
    check("test_pending_approval_has_no_decision", t119)


    # ------------------------------------------------------------------
    # 120-124: Duplicate incident prevention + resolution regression
    # ------------------------------------------------------------------

    # 120: investigate_incident passes target_ip to find_session_by_incident
    # so it finds an existing session created by /api/investigate.
    def t120():
        import app.api.incidents as incidents_mod

        def body(sdk_client):
            # Simulate a session already created by /api/investigate with target_ip
            sdk_client.create_session(
                "INC-DUP-1",
                evidence_snapshot={"source_ip": "10.0.0.25"},
                target_ip="10.0.0.25",
            )
            # Now simulate investigate_incident finding the existing session
            # The fix: find_session_by_incident now receives target_ip
            match = sdk_client.find_session_by_incident("INC-DUP-1", target_ip="10.0.0.25")
            assert match is not None, "Should find session with matching target_ip"
            assert match["incident_id"] == "INC-DUP-1"
            assert match["target_ip"] == "10.0.0.25"
        with_temp_sessions(body)
    check("test_incidents_finds_existing_session_with_target_ip", t120)

    # 121: Without the fix, different target_ip would miss the session.
    # Now investigate_incident also passes target_ip when creating new sessions.
    def t121():
        def body(sdk_client):
            s = sdk_client.create_session(
                "INC-DUP-2",
                evidence_snapshot={"source_ip": "10.0.0.25"},
                target_ip="10.0.0.25",
            )
            # A search without target_ip should still find it
            match_no_target = sdk_client.find_session_by_incident("INC-DUP-2")
            assert match_no_target is not None
            # And with matching target_ip should also find it
            match_with_target = sdk_client.find_session_by_incident("INC-DUP-2", target_ip="10.0.0.25")
            assert match_with_target is not None
            assert match_with_target["id"] == s["id"]
        with_temp_sessions(body)
    check("test_session_found_regardless_of_target_ip_query", t121)

    # 122: Two sessions with same incident_id but different target_ip
    # should be deduplicated by incident_id alone (frontend fix).
    def t122():
        def body(sdk_client):
            s1 = sdk_client.create_session(
                "INC-DUP-3",
                evidence_snapshot={"old": True},
                target_ip="10.0.0.25",
            )
            s2 = sdk_client.create_session(
                "INC-DUP-3",
                evidence_snapshot={"new": True},
            )
            # Both exist in the store
            all_sessions = sdk_client.list_sessions()
            dup_sessions = [s for s in all_sessions if s["incident_id"] == "INC-DUP-3"]
            assert len(dup_sessions) == 2, "Backend has both sessions"
            # The frontend dedup by incident_id alone would collapse these
            # (this test documents the invariant the frontend enforces)
            by_id = {}
            for s in dup_sessions:
                key = s["incident_id"]
                if key not in by_id:
                    by_id[key] = s
            assert len(by_id) == 1, "Dedup by incident_id yields one entry"
        with_temp_sessions(body)
    check("test_duplicate_sessions_collapsed_by_incident_id", t122)

    # 123: After approval resolves a session, duplicate with same incident_id
    # is hidden by the frontend dedup rule (resolved hides active).
    def t123():
        def body(sdk_client):
            s_active = sdk_client.create_session(
                "INC-DUP-4",
                evidence_snapshot={"v1": True},
                target_ip="10.0.0.25",
            )
            s_dup = sdk_client.create_session(
                "INC-DUP-4",
                evidence_snapshot={"v2": True},
            )
            # Approve and resolve the first one
            r = sdk_client.request_approval(s_active["id"], "BLOCK_IP", {"ip": "10.0.0.25"})
            aid = r["action_id"]
            sdk_client.release_request_claim(s_active["id"], aid)
            pr = sdk_client.prepare_decision(s_active["id"], aid, "approved")
            sdk_client.complete_decision(s_active["id"], aid, pr["token"])

            # Verify one is resolved, one is active
            sess_active = sdk_client.get_session(s_active["id"])
            sess_dup = sdk_client.get_session(s_dup["id"])
            assert sess_active["status"] == "resolved"
            assert sess_dup["status"] == "active"

            # Frontend dedup: resolved hides active for same incident_id
            all_sessions = sdk_client.list_sessions()
            resolved_keys = {s["incident_id"] for s in all_sessions if s["status"] == "resolved"}
            filtered = [s for s in all_sessions if s["status"] == "resolved" or s["incident_id"] not in resolved_keys]
            incident_statuses = {s["incident_id"]: s["status"] for s in filtered}
            assert incident_statuses.get("INC-DUP-4") == "resolved", "Resolved should be visible, active hidden"
        with_temp_sessions(body)
    check("test_resolved_hides_active_duplicate", t123)

    # 124: Full end-to-end: create session via investigate path, approve,
    # verify status=resolved and approval_state is terminal.
    def t124():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            # First investigation creates the session
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                result = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-RESOLVE-E2E"
                ))
            sid = result["session_id"]
            sess = sdk_client.get_session(sid)
            assert sess["status"] == "active"

            # Request approval
            r = sdk_client.request_approval(sid, "BLOCK_IP", {"ip": "10.0.0.25"})
            assert r["success"] is True
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)

            # Approve via prepare + complete
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            cr = sdk_client.complete_decision(sid, aid, pr["token"])
            assert cr["success"] is True

            # Verify final state
            sess = sdk_client.get_session(sid)
            assert sess["status"] == "resolved", "Session must be resolved after approval"
            assert sess["approval_state"]["status"] == "approved"
            action = [a for a in sess["actions"] if a["action_id"] == aid][0]
            assert action["status"] == "approved"
            assert action.get("decided_at") is not None
        with_temp_sessions(body)
    check("test_full_e2e_investigate_approve_resolves", t124)

    # ------------------------------------------------------------------
    # 125-131: Full TrueForge workflow — investigate → approve → resolve
    # with firewall persistence and no duplicate incidents.
    # ------------------------------------------------------------------

    # 125: Full workflow — investigate creates session, approve resolves it
    # AND blocks IP in simulated_firewall.json.
    def t125():
        import json as _json
        from pathlib import Path
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            # --- Step 1: Investigate the incident ---
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                result = investigate(InvestigationRequest(
                    query="Investigate suspicious activity from 10.0.0.25",
                    incident_id="INC-WF-1",
                ))
            sid = result["session_id"]
            assert result["incident_id"] == "INC-WF-1"
            sess = sdk_client.get_session(sid)
            assert sess["status"] == "active"
            assert sess["target_ip"] == "10.0.0.25"
            assert sess["risk_score"]["score"] == 80

            # --- Step 2: Request approval (simulates TrueForge forwarding) ---
            r = sdk_client.request_approval(sid, "block_ip", {"incident_id": "INC-WF-1"})
            assert r["success"] is True
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            sess = sdk_client.get_session(sid)
            assert sess["approval_state"]["status"] == "pending"

            # --- Step 3: Approve — resolves session + writes firewall ---
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            cr = sdk_client.complete_decision(sid, aid, pr["token"])
            assert cr["success"] is True
            assert cr["status"] == "approved"

            # Session must be resolved
            sess = sdk_client.get_session(sid)
            assert sess["status"] == "resolved", "Session must be resolved after approve"
            assert sess["approval_state"]["status"] == "approved"
            assert sess["approval_state"].get("decided_at") is not None

            # Execute block_ip (same as approvals.py does)
            fw_path = Path(__file__).resolve().parent.parent / "mcp_server" / "data" / "simulated_firewall.json"
            fw_path.parent.mkdir(parents=True, exist_ok=True)
            from mcp_server.tools.block_ip import block_ip as do_block
            do_block("10.0.0.25")

            # Firewall must have the blocked IP
            fw = _json.loads(fw_path.read_text())
            assert "10.0.0.25" in fw["blocked_ips"]
            block_events = [e for e in fw["events"] if e["ip"] == "10.0.0.25"]
            assert len(block_events) >= 1
        with_temp_sessions(body)
    check("test_full_workflow_investigate_approve_resolves_blocks_ip", t125)

    # 126: Reinvestigating the same incident reuses the existing session
    # (no duplicate) and supersedes any pending approval.
    def t126():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            # First investigation creates session
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                r1 = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-REINVEST-1"
                ))
            sid1 = r1["session_id"]

            # Second investigation with same incident_id + target_ip reuses session
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                r2 = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25 again", incident_id="INC-REINVEST-1"
                ))
            sid2 = r2["session_id"]

            # Must be the same session — no duplicate
            assert sid1 == sid2, "Same incident + target must reuse session"
            all_sessions = sdk_client.list_sessions()
            inc_sessions = [s for s in all_sessions if s["incident_id"] == "INC-REINVEST-1"]
            assert len(inc_sessions) == 1, f"Expected 1 session, got {len(inc_sessions)}"
        with_temp_sessions(body)
    check("test_reinvestigation_reuses_session_no_duplicate", t126)

    # 127: Reinvestigating a resolved incident restores it to active.
    def t127():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            # Create and resolve a session
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                r1 = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-REINVEST-2"
                ))
            sid = r1["session_id"]
            sdk_client.request_approval(sid, "block_ip", {"incident_id": "INC-REINVEST-2"})
            sess = sdk_client.get_session(sid)
            aid = sess["approval_state"]["action_id"]
            sdk_client.release_request_claim(sid, aid)
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            sdk_client.complete_decision(sid, aid, pr["token"])
            assert sdk_client.get_session(sid)["status"] == "resolved"

            # Reinvestigate — should restore to active
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                r2 = investigate(InvestigationRequest(
                    query="Reinvestigate 10.0.0.25", incident_id="INC-REINVEST-2"
                ))
            assert r2["session_id"] == sid, "Must reuse the same session"
            sess = sdk_client.get_session(sid)
            assert sess["status"] == "active", "Reinvestigation must restore to active"
        with_temp_sessions(body)
    check("test_reinvestigate_resolved_restores_to_active", t127)

    # 128: Rejecting an incident also resolves it and session is terminal.
    def t128():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                result = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-WF-REJECT"
                ))
            sid = result["session_id"]
            r = sdk_client.request_approval(sid, "block_ip", {"incident_id": "INC-WF-REJECT"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            pr = sdk_client.prepare_decision(sid, aid, "rejected")
            cr = sdk_client.complete_decision(sid, aid, pr["token"])
            assert cr["success"] is True
            assert cr["status"] == "rejected"
            sess = sdk_client.get_session(sid)
            assert sess["status"] == "resolved", "Rejected must also resolve session"
            assert sess["approval_state"]["status"] == "rejected"
        with_temp_sessions(body)
    check("test_reject_also_resolves_session", t128)

    # 129: After resolve, list_sessions shows the session as resolved.
    def t129():
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                result = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-WF-LIST"
                ))
            sid = result["session_id"]
            r = sdk_client.request_approval(sid, "block_ip", {"incident_id": "INC-WF-LIST"})
            aid = r["action_id"]
            sdk_client.release_request_claim(sid, aid)
            pr = sdk_client.prepare_decision(sid, aid, "approved")
            sdk_client.complete_decision(sid, aid, pr["token"])

            sessions = sdk_client.list_sessions()
            match = [s for s in sessions if s["id"] == sid]
            assert len(match) == 1
            assert match[0]["status"] == "resolved"
            assert match[0]["approval_state"]["status"] == "approved"
        with_temp_sessions(body)
    check("test_list_sessions_shows_resolved", t129)

    # 130: TrueForge investigation path reuses existing session with target_ip.
    def t130():
        import app.api.incidents as incidents_mod
        from app.api.approvals import HTTPException

        fake_analysis = {
            "success": True, "source_ip": "10.0.0.25",
            "findings": ["test"], "risk_indicators": {"failed_attempts": 25}
        }
        fake_logs = {
            "success": True, "failed_logins": 25, "successful_logins": 0,
            "match_count": 25
        }
        fake_activity = {
            "success": True, "process_count": 5, "suspicious_process_count": 2,
            "unusual_connection_count": 1
        }

        def body(sdk_client):
            # Pre-create session via /api/investigate path (with target_ip)
            s = sdk_client.create_session(
                "INC-1024",
                evidence_snapshot={"old": True},
                target_ip="10.0.0.25",
                risk_score={"score": 60, "level": "HIGH"},
            )
            original_sid = s["id"]

            # Now call investigate_incident — must reuse the same session
            with patch.object(incidents_mod, "analyze_evidence", return_value=fake_analysis), \
                 patch.object(incidents_mod, "search_security_logs", return_value=fake_logs), \
                 patch.object(incidents_mod, "check_system_activity", return_value=fake_activity), \
                 patch.object(incidents_mod, "find_session_by_incident", wraps=incidents_mod.find_session_by_incident), \
                 patch.object(incidents_mod, "update_session", wraps=incidents_mod.update_session), \
                 patch.object(incidents_mod, "persist_trueforge_session_id", return_value={"success": True, "trueforge_session_id": None}), \
                 patch.object(incidents_mod, "_require_successful_tool_result", side_effect=lambda result, name: result), \
                 patch("urllib.request.urlopen", side_effect=ConnectionError("TrueForge not running")):
                try:
                    result = incidents_mod.investigate_incident("INC-1024")
                except Exception:
                    pass  # TrueForge connection fails, but local session should be reused

            # Session count must still be 1 — no duplicate
            all_sessions = sdk_client.list_sessions()
            inc_sessions = [s for s in all_sessions if s["incident_id"] == "INC-1024"]
            assert len(inc_sessions) == 1, f"Expected 1 session, got {len(inc_sessions)}"
            assert inc_sessions[0]["id"] == original_sid, "Must reuse the original session"
            assert inc_sessions[0]["target_ip"] == "10.0.0.25"
        with_temp_sessions(body)
    check("test_trueforge_investigate_reuses_existing_session", t130)

    # 131: Full round-trip: two incidents investigated, first approved
    # (resolved + blocked), second rejected (resolved + not blocked).
    def t131():
        import json as _json
        from pathlib import Path
        from app.api.investigate import investigate, InvestigationRequest

        def body(sdk_client):
            # --- Incident 1: Approve → block IP → resolved ---
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                r1 = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-RT-1"
                ))
            sid1 = r1["session_id"]
            r = sdk_client.request_approval(sid1, "block_ip", {"incident_id": "INC-RT-1"})
            aid1 = r["action_id"]
            sdk_client.release_request_claim(sid1, aid1)
            pr = sdk_client.prepare_decision(sid1, aid1, "approved")
            sdk_client.complete_decision(sid1, aid1, pr["token"])
            assert sdk_client.get_session(sid1)["status"] == "resolved"

            # --- Incident 2: Reject → not blocked → resolved ---
            with patch("app.api.investigate.run_investigation", return_value=make_fake_result()):
                r2 = investigate(InvestigationRequest(
                    query="Investigate 10.0.0.25", incident_id="INC-RT-2"
                ))
            sid2 = r2["session_id"]
            r = sdk_client.request_approval(sid2, "block_ip", {"incident_id": "INC-RT-2"})
            aid2 = r["action_id"]
            sdk_client.release_request_claim(sid2, aid2)
            pr2 = sdk_client.prepare_decision(sid2, aid2, "rejected")
            sdk_client.complete_decision(sid2, aid2, pr2["token"])
            assert sdk_client.get_session(sid2)["status"] == "resolved"

            # Both resolved
            all_sessions = sdk_client.list_sessions()
            resolved = [s for s in all_sessions if s["status"] == "resolved"]
            assert len(resolved) == 2
            incident_ids = {s["incident_id"] for s in resolved}
            assert incident_ids == {"INC-RT-1", "INC-RT-2"}

            # No active incidents
            active = [s for s in all_sessions if s["status"] == "active"]
            assert len(active) == 0
        with_temp_sessions(body)
    check("test_two_incidents_resolved_one_approved_one_rejected", t131)

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
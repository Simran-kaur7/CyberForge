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

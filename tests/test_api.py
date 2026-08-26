"""Tests for CyberForge SDK Client (session & approval management)."""

import sys
import json
import tempfile
from pathlib import Path
# monkeypatch is a pytest concept; tests use temp files instead

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))


def run_all():
    """Run SDK client tests manually."""
    # Import after path setup
    import sdk_client

    passed = 0
    failed = 0
    errors = []

    # Use a temp file for sessions to avoid polluting real data
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_sessions = Path(tmpdir) / "sessions.json"
        original_sessions_file = sdk_client.SESSIONS_FILE
        sdk_client.SESSIONS_FILE = tmp_sessions

        try:
            # Test 1: List empty sessions
            try:
                sessions = sdk_client.list_sessions()
                assert sessions == [], f"Expected empty list, got {sessions}"
                print("  PASS  test_list_empty_sessions")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_list_empty_sessions: {e}")
                failed += 1
                errors.append(str(e))

            # Test 2: Create a session
            try:
                session = sdk_client.create_session("INC-1024", {"source_ip": "10.0.0.25"})
                assert session["incident_id"] == "INC-1024"
                assert session["status"] == "active"
                assert session["id"] is not None
                assert len(session["id"]) == 8
                print("  PASS  test_create_session")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_create_session: {e}")
                failed += 1
                errors.append(str(e))

            # Test 3: Get session by ID
            try:
                fetched = sdk_client.get_session(session["id"])
                assert fetched is not None
                assert fetched["incident_id"] == "INC-1024"
                print("  PASS  test_get_session")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_get_session: {e}")
                failed += 1
                errors.append(str(e))

            # Test 4: List sessions shows the created one
            try:
                sessions = sdk_client.list_sessions()
                assert len(sessions) == 1
                assert sessions[0]["incident_id"] == "INC-1024"
                print("  PASS  test_list_sessions")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_list_sessions: {e}")
                failed += 1
                errors.append(str(e))

            # Test 5: Find session by incident ID
            try:
                found = sdk_client.find_session_by_incident("INC-1024")
                assert found is not None
                assert found["id"] == session["id"]
                print("  PASS  test_find_session_by_incident")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_find_session_by_incident: {e}")
                failed += 1
                errors.append(str(e))

            # Test 6: Request approval
            try:
                result = sdk_client.request_approval(
                    session["id"], "BLOCK_IP", {"ip_address": "10.0.0.25"}
                )
                assert result["success"] is True
                assert result["status"] == "pending"
                action_id = result["action_id"]
                print("  PASS  test_request_approval")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_request_approval: {e}")
                failed += 1
                errors.append(str(e))

            # Test 7: Approve action
            try:
                approve_result = sdk_client.approve_action(session["id"], action_id)
                assert approve_result["success"] is True
                assert approve_result["status"] == "approved"
                print("  PASS  test_approve_action")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_approve_action: {e}")
                failed += 1
                errors.append(str(e))

            # Test 8: Session reflects approval
            try:
                updated = sdk_client.get_session(session["id"])
                assert updated["approval_state"]["status"] == "approved"
                assert updated["approval_state"]["decided_by"] == "analyst"
                print("  PASS  test_session_reflects_approval")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_session_reflects_approval: {e}")
                failed += 1
                errors.append(str(e))

            # Test 9: Reject a new action
            try:
                result2 = sdk_client.request_approval(
                    session["id"], "ISOLATE_HOST", {"host": "web-server-01"}
                )
                reject_result = sdk_client.reject_action(session["id"], result2["action_id"])
                assert reject_result["success"] is True
                assert reject_result["status"] == "rejected"
                print("  PASS  test_reject_action")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_reject_action: {e}")
                failed += 1
                errors.append(str(e))

            # Test 10: Get nonexistent session
            try:
                result = sdk_client.get_session("nonexistent")
                assert result is None
                print("  PASS  test_get_nonexistent_session")
                passed += 1
            except Exception as e:
                print(f"  FAIL  test_get_nonexistent_session: {e}")
                failed += 1
                errors.append(str(e))

        finally:
            sdk_client.SESSIONS_FILE = original_sessions_file

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for e in errors:
            print(f"  - {e}")
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)

import sqlite3

from fastapi.testclient import TestClient

from rygnal.api import create_app
from rygnal.approval_queue import InMemoryApprovalQueue, SQLiteApprovalQueue
from rygnal.audit_logger import AuditLogger
from rygnal.models import ApprovalRequest, Severity


def make_request(
    *,
    requested_by: str = "agent_user",
    reason: str = "Risky guarded workspace patch requires approval.",
) -> ApprovalRequest:
    return ApprovalRequest(
        requested_by=requested_by,
        agent_id="agent_1",
        environment="local",
        trace_id="trace_approval_api",
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target="patch_sha256_demo",
        policy_id="guarded-workspace-risky-patch-approval",
        reason=reason,
        severity=Severity.HIGH,
        risk_assessment={
            "risk_level": "high",
            "summary": "Risky guarded workspace patch requires approval.",
        },
        metadata={
            "patch_sha256": "patch_sha256_demo",
            "api_key": "sk-live-super-secret-token",
        },
    )


def test_local_api_approval_queue_creates_and_lists_pending_requests_redacted():
    queue = InMemoryApprovalQueue()
    client = TestClient(create_app(approval_queue=queue))

    create_response = client.post("/v1/approvals", json=make_request().model_dump(mode="json"))
    assert create_response.status_code == 201

    created = create_response.json()["approval"]
    assert created["status"] == "pending"
    assert "sk-live-super-secret-token" not in create_response.text
    assert created["request"]["metadata"]["api_key"] == "[REDACTED]"

    response = client.get("/v1/approvals")
    data = response.json()

    assert response.status_code == 200
    assert data["returned_count"] == 1
    assert data["approvals"][0]["approval_id"] == created["approval_id"]
    assert data["approvals"][0]["status"] == "pending"
    assert "sk-live-super-secret-token" not in response.text


def test_local_api_approval_queue_gets_one_request():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    response = client.get(f"/v1/approvals/{request.approval_id}")
    data = response.json()

    assert response.status_code == 200
    assert data["approval"]["approval_id"] == request.approval_id
    assert data["approval"]["status"] == "pending"


def test_local_api_approval_queue_returns_404_for_missing_request():
    client = TestClient(create_app(approval_queue=InMemoryApprovalQueue()))

    response = client.get(
        "/v1/approvals/app_missing",
        headers={"X-Request-ID": "req_missing_approval"},
    )

    data = response.json()

    assert response.status_code == 404
    assert data["error"]["code"] == "approval_not_found"
    assert data["error"]["request_id"] == "req_missing_approval"


def test_local_api_approval_queue_approves_request():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "human_reviewer",
            "reason": "Looks safe after review.",
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert data["approval_decision"]["approval_id"] == request.approval_id
    assert data["approval_decision"]["status"] == "approved"
    assert data["approval"]["status"] == "approved"

    fetched = client.get(f"/v1/approvals/{request.approval_id}").json()
    assert fetched["approval"]["status"] == "approved"


def test_local_api_approval_queue_rejects_request():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/reject",
        json={
            "decided_by": "human_reviewer",
            "reason": "Not safe enough.",
        },
    )

    data = response.json()

    assert response.status_code == 200
    assert data["approval_decision"]["status"] == "rejected"
    assert data["approval"]["status"] == "rejected"


def test_local_api_approval_queue_rejects_self_approval_safely():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request(requested_by="agent_user"))
    client = TestClient(create_app(approval_queue=queue))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "agent_user",
            "reason": "Trying to approve my own request.",
        },
        headers={"X-Request-ID": "req_self_approval"},
    )

    data = response.json()

    assert response.status_code == 403
    assert data["error"]["code"] == "approval_denied"
    assert data["error"]["request_id"] == "req_self_approval"
    assert "own approval request" in data["error"]["message"].lower()

    fetched = client.get(f"/v1/approvals/{request.approval_id}").json()
    assert fetched["approval"]["status"] == "pending"


def test_local_api_approval_queue_rejects_double_decision():
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue))

    first = client.post(
        f"/v1/approvals/{request.approval_id}/reject",
        json={
            "decided_by": "human_reviewer",
            "reason": "Not safe.",
        },
    )
    assert first.status_code == 200

    second = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "another_reviewer",
            "reason": "Changed mind.",
        },
    )

    data = second.json()

    assert second.status_code == 409
    assert data["error"]["code"] == "approval_state_conflict"


def test_local_api_approval_queue_approve_writes_redacted_audit_event(tmp_path):
    audit_logger = AuditLogger(tmp_path / "approval_api_audit.jsonl")
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue, audit_logger=audit_logger))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "human_reviewer",
            "reason": "Approved with sk-live-super-secret-token after review.",
        },
    )

    data = response.json()
    events = audit_logger.read_events()

    assert response.status_code == 200
    assert data["audit_event"] is not None
    assert data["audit_event"]["action"] == "approval_decided"
    assert data["audit_event"]["decision"] == "allow"
    assert data["audit_event"]["allowed"] is True
    assert data["audit_event"]["metadata"]["approval_decision"]["status"] == "approved"
    assert len(events) == 1
    assert events[0].action == "approval_decided"
    assert events[0].allowed is True
    assert "sk-live-super-secret-token" not in response.text
    assert "sk-live-super-secret-token" not in events[0].model_dump_json()


def test_local_api_approval_queue_reject_writes_redacted_audit_event(tmp_path):
    audit_logger = AuditLogger(tmp_path / "approval_api_audit.jsonl")
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request())
    client = TestClient(create_app(approval_queue=queue, audit_logger=audit_logger))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/reject",
        json={
            "decided_by": "human_reviewer",
            "reason": "Rejected with sk-live-super-secret-token after review.",
        },
    )

    data = response.json()
    events = audit_logger.read_events()

    assert response.status_code == 200
    assert data["audit_event"] is not None
    assert data["audit_event"]["action"] == "approval_decided"
    assert data["audit_event"]["decision"] == "block"
    assert data["audit_event"]["allowed"] is False
    assert data["audit_event"]["metadata"]["approval_decision"]["status"] == "rejected"
    assert len(events) == 1
    assert events[0].action == "approval_decided"
    assert events[0].allowed is False
    assert "sk-live-super-secret-token" not in response.text
    assert "sk-live-super-secret-token" not in events[0].model_dump_json()


def test_local_api_approval_queue_denied_self_approval_does_not_write_audit_event(tmp_path):
    audit_logger = AuditLogger(tmp_path / "approval_api_audit.jsonl")
    queue = InMemoryApprovalQueue()
    request = queue.submit(make_request(requested_by="agent_user"))
    client = TestClient(create_app(approval_queue=queue, audit_logger=audit_logger))

    response = client.post(
        f"/v1/approvals/{request.approval_id}/approve",
        json={
            "decided_by": "agent_user",
            "reason": "Trying to approve my own request.",
        },
    )

    assert response.status_code == 403
    assert audit_logger.read_events() == []


def test_sqlite_approval_queue_persists_pending_requests_across_restart(tmp_path):
    db_path = tmp_path / "approval_queue.db"
    first_client = TestClient(create_app(approval_queue=SQLiteApprovalQueue(db_path)))

    create_response = first_client.post(
        "/v1/approvals", json=make_request().model_dump(mode="json")
    )
    assert create_response.status_code == 201
    approval_id = create_response.json()["approval"]["approval_id"]

    second_client = TestClient(create_app(approval_queue=SQLiteApprovalQueue(db_path)))
    fetched = second_client.get(f"/v1/approvals/{approval_id}")
    listed = second_client.get("/v1/approvals")

    assert fetched.status_code == 200
    assert fetched.json()["approval"]["approval_id"] == approval_id
    assert fetched.json()["approval"]["status"] == "pending"
    assert listed.json()["returned_count"] == 1
    assert listed.json()["approvals"][0]["approval_id"] == approval_id


def test_create_app_approval_queue_db_path_persists_decisions_across_restart(tmp_path):
    db_path = tmp_path / "approval_queue.db"
    first_client = TestClient(create_app(approval_queue_db_path=db_path))

    create_response = first_client.post(
        "/v1/approvals", json=make_request().model_dump(mode="json")
    )
    assert create_response.status_code == 201
    approval_id = create_response.json()["approval"]["approval_id"]

    approve_response = first_client.post(
        f"/v1/approvals/{approval_id}/approve",
        json={
            "decided_by": "human_reviewer",
            "reason": "Looks safe after review.",
        },
    )
    assert approve_response.status_code == 200

    second_client = TestClient(create_app(approval_queue_db_path=db_path))
    fetched = second_client.get(f"/v1/approvals/{approval_id}")
    second_decision = second_client.post(
        f"/v1/approvals/{approval_id}/reject",
        json={
            "decided_by": "another_reviewer",
            "reason": "Changed mind after restart.",
        },
    )

    assert fetched.status_code == 200
    assert fetched.json()["approval"]["status"] == "approved"
    assert fetched.json()["approval"]["approval_decision"]["status"] == "approved"
    assert second_decision.status_code == 409
    assert second_decision.json()["error"]["code"] == "approval_state_conflict"


def test_sqlite_approval_queue_persists_redacted_request_payload(tmp_path):
    db_path = tmp_path / "approval_queue.db"
    queue = SQLiteApprovalQueue(db_path)
    queue.submit(make_request())

    with sqlite3.connect(db_path) as connection:
        row = connection.execute("SELECT request_json FROM approval_queue").fetchone()

    assert row is not None
    request_json = row[0]
    assert "sk-live-super-secret-token" not in request_json
    assert "[REDACTED]" in request_json

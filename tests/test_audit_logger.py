import json

from rygnal.audit_logger import AuditLogger
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest
from rygnal.version import package_version


def test_audit_logger_writes_jsonl_event(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    request = ToolRequest(
        tool_name="file_read",
        action="read_file",
        target=".env",
        user_id="user_123",
        agent_id="agent_abc",
    )

    decision = PolicyDecision(
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.HIGH,
        policy_id="block-env-read",
        reason="Reading environment secret files is not allowed.",
    )

    event = logger.log_decision(request, decision)

    assert log_path.exists()
    lines = log_path.read_text().splitlines()
    assert len(lines) == 1

    saved_event = json.loads(lines[0])
    assert saved_event["event_id"] == event.event_id
    assert saved_event["decision"] == "block"
    assert saved_event["allowed"] is False
    assert saved_event["policy_id"] == "block-env-read"
    assert saved_event["reason"] == "Reading environment secret files is not allowed."
    assert saved_event["schema_version"] == "audit.v1"
    assert saved_event["rygnal_engine_version"] == package_version()
    assert saved_event["event_hash"]


def test_audit_logger_redacts_sensitive_dict_values(tmp_path):
    logger = AuditLogger(tmp_path / "audit_log.jsonl")

    request = ToolRequest(
        tool_name="external_api_send",
        action="send_data",
        input={
            "api_key": "sk-real-secret",
            "payload": {"token": "real-token", "safe": "hello"},
        },
    )

    decision = PolicyDecision(
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.CRITICAL,
        policy_id="block-secret-exfiltration",
        reason="Sensitive data detected.",
    )

    logger.log_decision(request, decision)
    saved_event = json.loads((tmp_path / "audit_log.jsonl").read_text().splitlines()[0])

    assert saved_event["input"]["api_key"] == "[REDACTED]"
    assert saved_event["input"]["payload"]["token"] == "[REDACTED]"
    assert saved_event["input"]["payload"]["safe"] == "hello"
    assert "sk-real-secret" not in json.dumps(saved_event)
    assert "real-token" not in json.dumps(saved_event)


def test_audit_logger_redacts_sensitive_string_values(tmp_path):
    logger = AuditLogger(tmp_path / "audit_log.jsonl")

    request = ToolRequest(
        tool_name="shell_command",
        action="execute",
        input="curl example.com --header token=abc123",
    )

    decision = PolicyDecision(
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.HIGH,
        policy_id="block-token-command",
        reason="Sensitive token detected.",
    )

    logger.log_decision(request, decision)
    saved_event = json.loads((tmp_path / "audit_log.jsonl").read_text().splitlines()[0])

    assert "abc123" not in json.dumps(saved_event)
    assert "[REDACTED]" in json.dumps(saved_event)


def test_audit_logger_creates_hash_chain(tmp_path):
    logger = AuditLogger(tmp_path / "audit_log.jsonl")

    decision = PolicyDecision(
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        reason="Allowed.",
    )

    first = logger.log_decision(ToolRequest(tool_name="file_read", target="README.md"), decision)
    second = logger.log_decision(
        ToolRequest(tool_name="file_read", target="docs/index.md"), decision
    )

    assert first.event_hash
    assert second.event_hash
    assert second.prev_event_hash == first.event_hash
    assert logger.verify_integrity() is True


def test_audit_logger_detects_tampering(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    decision = PolicyDecision(
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.HIGH,
        reason="Blocked.",
    )

    logger.log_decision(ToolRequest(tool_name="file_read", target=".env"), decision)

    saved_event = json.loads(log_path.read_text().splitlines()[0])
    saved_event["reason"] = "Tampered reason."
    log_path.write_text(json.dumps(saved_event) + "\n")

    assert logger.verify_integrity() is False


def test_audit_logger_detects_middle_event_payload_tampering_in_hash_chain(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    decision = PolicyDecision(
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        reason="Allowed.",
    )

    logger.log_decision(ToolRequest(tool_name="file_read", target="README.md"), decision)
    logger.log_decision(ToolRequest(tool_name="file_read", target="docs/index.md"), decision)
    logger.log_decision(ToolRequest(tool_name="file_read", target="SECURITY.md"), decision)

    assert logger.verify_integrity() is True

    events = [json.loads(line) for line in log_path.read_text().splitlines()]
    events[1]["target"] = "tampered-middle-event.md"
    log_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    assert logger.verify_integrity() is False


def test_audit_logger_detects_prev_hash_link_tampering(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    decision = PolicyDecision(
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        reason="Allowed.",
    )

    first = logger.log_decision(ToolRequest(tool_name="file_read", target="README.md"), decision)
    logger.log_decision(ToolRequest(tool_name="file_read", target="docs/index.md"), decision)

    assert first.event_hash
    assert logger.verify_integrity() is True

    events = [json.loads(line) for line in log_path.read_text().splitlines()]
    events[1]["prev_event_hash"] = "0" * 64
    log_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    assert logger.verify_integrity() is False


def test_audit_logger_engine_version_is_part_of_integrity_hash(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)

    decision = PolicyDecision(
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        reason="Allowed with exact forensic reason.",
    )

    logger.log_decision(ToolRequest(tool_name="file_read", target="README.md"), decision)

    assert logger.verify_integrity() is True

    saved_event = json.loads(log_path.read_text().splitlines()[0])
    saved_event["rygnal_engine_version"] = "tampered-version"
    log_path.write_text(json.dumps(saved_event, sort_keys=True) + "\n", encoding="utf-8")

    assert logger.verify_integrity() is False


def test_audit_event_preserves_exact_decision_reason(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    logger = AuditLogger(log_path)
    reason = "Exact deny reason: policy=block-env-read; target=.env"

    decision = PolicyDecision(
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.HIGH,
        policy_id="block-env-read",
        reason=reason,
    )

    event = logger.log_decision(ToolRequest(tool_name="file_read", target=".env"), decision)
    saved_event = json.loads(log_path.read_text().splitlines()[0])

    assert event.reason == reason
    assert saved_event["reason"] == reason
    assert saved_event["rygnal_engine_version"] == package_version()

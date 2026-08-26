from rygnal.execution_backend import ExecutionBackendName
from rygnal.process_containment import (
    CleanupGuarantee,
    ContainmentLevel,
    LifecycleEvent,
    build_lifecycle_result,
    evaluate_containment_capabilities,
)


def test_unsafe_local_reports_best_effort_cleanup_only() -> None:
    caps = evaluate_containment_capabilities(ExecutionBackendName.UNSAFE_LOCAL)

    assert caps.level == ContainmentLevel.BEST_EFFORT
    assert caps.cleanup_guarantee == CleanupGuarantee.POSIX_PROCESS_GROUP
    assert caps.supports_pid_namespace is False
    assert caps.supports_atomic_tree_kill is False
    assert caps.unsafe_local is True

    limitation_text = " ".join(caps.limitations)
    assert "POSIX process groups are not a security boundary" in limitation_text
    assert "double-fork" in limitation_text
    assert "setsid" in limitation_text


def test_unsafe_local_does_not_mark_containment_verified_on_success() -> None:
    caps = evaluate_containment_capabilities(ExecutionBackendName.UNSAFE_LOCAL)
    result = build_lifecycle_result(caps, LifecycleEvent.COMPLETED)

    assert result.event == LifecycleEvent.COMPLETED
    assert result.containment_verified is False
    assert "unverified containment" in result.audit_message
    assert "best-effort" in result.audit_message


def test_unsupported_backend_returns_unsupported_containment() -> None:
    caps = evaluate_containment_capabilities(ExecutionBackendName.CONFIGURED_CONTAINER)

    assert caps.level == ContainmentLevel.UNSUPPORTED
    assert caps.cleanup_guarantee == CleanupGuarantee.NONE
    assert caps.supports_atomic_tree_kill is False
    assert "unverified or unavailable" in caps.limitations[0]


def test_timeout_on_unsafe_local_produces_best_effort_and_limitations() -> None:
    caps = evaluate_containment_capabilities(ExecutionBackendName.UNSAFE_LOCAL)
    result = build_lifecycle_result(caps, LifecycleEvent.TIMED_OUT)

    assert result.event == LifecycleEvent.TIMED_OUT
    assert result.containment_verified is False
    assert result.cleanup_guarantee == CleanupGuarantee.POSIX_PROCESS_GROUP

    limitation_text = " ".join(result.limitations)
    assert "Detached children" in limitation_text


def test_model_prevents_parent_only_kill_from_claiming_security() -> None:
    caps = evaluate_containment_capabilities(ExecutionBackendName.UNSAFE_LOCAL)
    result = build_lifecycle_result(caps, LifecycleEvent.CANCELLED)

    assert result.cleanup_guarantee == CleanupGuarantee.POSIX_PROCESS_GROUP
    assert result.containment_verified is False
    assert any("Parent exit code 0 does not guarantee" in lim for lim in result.limitations)

"""Process-tree containment modeling and enforcement for guarded execution.

This module defines the strict security boundaries for process execution.
POSIX process groups, sessions, and `killpg()` are NOT security boundaries;
they are easily bypassed via `setsid()`, double-forking, or backgrounding.

True guarded execution requires atomic tree-kill capabilities, primarily
provided by Linux PID namespaces (e.g., Bubblewrap) or `cgroups`. Backends
lacking these primitives must explicitly report leaky containment boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from rygnal.execution_backend import ExecutionBackendName


class ContainmentLevel(StrEnum):
    """The strictness of the containment boundary."""

    STRONG = "strong"
    BEST_EFFORT = "best_effort"
    UNSUPPORTED = "unsupported"


class CleanupGuarantee(StrEnum):
    """The mechanism used to terminate the process tree."""

    ATOMIC_TREE_KILL = "atomic_tree_kill"
    POSIX_PROCESS_GROUP = "posix_process_group"
    NONE = "none"


class LifecycleEvent(StrEnum):
    """Execution lifecycle stages mapped to containment audits."""

    STARTED = "started"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    CLEANUP_ATTEMPTED = "cleanup_attempted"


@dataclass(frozen=True)
class ProcessContainmentCapabilities:
    """The physical containment primitives available to the current backend."""

    backend_name: ExecutionBackendName
    level: ContainmentLevel
    cleanup_guarantee: CleanupGuarantee
    supports_pid_namespace: bool
    supports_atomic_tree_kill: bool
    unsafe_local: bool
    limitations: tuple[str, ...]
    network_isolated: bool = False
    ipc_namespace: bool = False
    uts_namespace: bool = False
    tmpfs_isolated: bool = False
    var_tmpfs_isolated: bool = False
    dev_sandboxed: bool = False
    identity_masked: bool = False
    host_environment_cleared: bool = False
    workspace_only_writable: bool = False

    @property
    def isolation_features(
        self,
    ) -> dict[str, bool]:
        """Return the established backend feature contract."""
        return {
            "network_isolated": self.network_isolated,
            "pid_namespace": (self.supports_pid_namespace),
            "ipc_namespace": self.ipc_namespace,
            "uts_namespace": self.uts_namespace,
            "tmpfs_isolated": self.tmpfs_isolated,
            "var_tmpfs_isolated": (self.var_tmpfs_isolated),
            "dev_sandboxed": self.dev_sandboxed,
            "identity_masked": self.identity_masked,
            "host_environment_cleared": (self.host_environment_cleared),
            "workspace_only_writable": (self.workspace_only_writable),
            "atomic_tree_kill": (self.supports_atomic_tree_kill),
        }


@dataclass(frozen=True)
class ProcessContainmentResult:
    """The audited result of a lifecycle event, enforcing containment reality."""

    event: LifecycleEvent
    containment_verified: bool
    cleanup_guarantee: CleanupGuarantee
    limitations: tuple[str, ...]
    audit_message: str


def evaluate_containment_capabilities(
    backend: ExecutionBackendName,
) -> ProcessContainmentCapabilities:
    """Evaluate backend capabilities, preventing POSIX groups from claiming security."""

    if backend in {
        ExecutionBackendName.LINUX_BUBBLEWRAP,
        ExecutionBackendName.LINUX_BUBBLEWRAP_HELPER,
    }:
        return ProcessContainmentCapabilities(
            backend_name=backend,
            level=ContainmentLevel.STRONG,
            cleanup_guarantee=CleanupGuarantee.ATOMIC_TREE_KILL,
            supports_pid_namespace=True,
            supports_atomic_tree_kill=True,
            unsafe_local=False,
            limitations=(),
            network_isolated=True,
            ipc_namespace=True,
            uts_namespace=True,
            tmpfs_isolated=True,
            var_tmpfs_isolated=True,
            dev_sandboxed=True,
            identity_masked=True,
            host_environment_cleared=True,
            workspace_only_writable=True,
        )

    if backend == ExecutionBackendName.LINUX_SYSTEMD_USER:
        return ProcessContainmentCapabilities(
            backend_name=backend,
            level=ContainmentLevel.STRONG,
            cleanup_guarantee=CleanupGuarantee.ATOMIC_TREE_KILL,
            supports_pid_namespace=False,
            supports_atomic_tree_kill=True,  # cgroups v2 guarantee atomic kill
            unsafe_local=False,
            limitations=(),
        )

    if backend == ExecutionBackendName.UNSAFE_LOCAL:
        return ProcessContainmentCapabilities(
            backend_name=backend,
            level=ContainmentLevel.BEST_EFFORT,
            cleanup_guarantee=CleanupGuarantee.POSIX_PROCESS_GROUP,
            supports_pid_namespace=False,
            supports_atomic_tree_kill=False,
            unsafe_local=True,
            limitations=(
                "POSIX process groups are not a security boundary.",
                "Detached children (double-fork, setsid, nohup) may survive "
                "timeout or cancellation.",
                "Parent exit code 0 does not guarantee child processes are terminated.",
                "Manual /proc PID-tree scanning is race-prone and disabled "
                "for security enforcement.",
            ),
        )

    # CONFIGURED_CONTAINER or unknown backends without explicit tree-kill verification
    return ProcessContainmentCapabilities(
        backend_name=backend,
        level=ContainmentLevel.UNSUPPORTED,
        cleanup_guarantee=CleanupGuarantee.NONE,
        supports_pid_namespace=False,
        supports_atomic_tree_kill=False,
        unsafe_local=False,
        limitations=(
            "Full process-tree containment is unverified or unavailable for this backend.",
            "Execution must fail closed unless explicitly overridden.",
        ),
    )


def build_lifecycle_result(
    capabilities: ProcessContainmentCapabilities,
    event: LifecycleEvent,
) -> ProcessContainmentResult:
    """
    Build a secure lifecycle audit result.
    Prevents "Success Desync" by ensuring a parent exit code of 0 cannot
    falsely claim verified containment if the backend leaks child processes.
    """
    verified = capabilities.supports_atomic_tree_kill

    if verified:
        audit = f"Process {event.value} with verified containment (Atomic Tree Kill)."
    else:
        audit = (
            f"Process {event.value} with unverified containment. "
            f"Cleanup is best-effort ({capabilities.cleanup_guarantee.value})."
        )

    return ProcessContainmentResult(
        event=event,
        containment_verified=verified,
        cleanup_guarantee=capabilities.cleanup_guarantee,
        limitations=capabilities.limitations,
        audit_message=audit,
    )

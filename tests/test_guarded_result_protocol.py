from __future__ import annotations

import sys
from pathlib import Path

from rygnal.cli_run import to_safe_json_summary
from rygnal.guarded_runner import (
    GuardedRunConfig,
    run_guarded,
)
from tests.guarded_runner_helpers import (
    create_trusted_repo,
)


def test_cli_json_protocol_exposes_applied_patch(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=trusted,
            command=(
                sys.executable,
                "-c",
                ("from pathlib import Path; Path('protocol.txt').write_text('ok')"),
            ),
            timeout_seconds=5,
            rygnal_run_root=tmp_path / "runs",
            unsafe_local_requested=True,
        )
    )

    summary = to_safe_json_summary(result)

    assert summary["patch"]["generated"] is True
    assert summary["patch"]["apply_outcome"] == "applied"
    assert summary["patch"]["applied"] is True
    assert summary["patch"]["artifact_id"] is None
    assert summary["cleanup"]["performed"] is True
    assert summary["cleanup"]["status"] == "worktree_removed"
    assert summary["cleanup"]["quarantined"] is False

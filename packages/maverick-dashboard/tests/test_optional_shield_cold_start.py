"""Cold-process proof that the dashboard does not depend on optional Shield."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_stock_vendor_authority_survives_cold_start_without_optional_shield():
    repo = Path(__file__).resolve().parents[3]
    target = "packages/maverick-dashboard/tests/test_vendor_onboarding_api.py"
    script = r"""
import importlib.abc
import sys

class BlockShield(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "maverick_shield" or fullname.startswith("maverick_shield."):
            raise ImportError("optional shield is unavailable during cold start")
        return None

sys.meta_path.insert(0, BlockShield())
import pytest
raise SystemExit(pytest.main(sys.argv[1:]))
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            f"{target}::test_current_workspace_can_accept_existing_effect_after_switch_back",
            (
                f"{target}::test_stock_worker_rechecks_revoked_membership_before_effect"
                "[before_claim]"
            ),
            "-q",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "2 passed" in output

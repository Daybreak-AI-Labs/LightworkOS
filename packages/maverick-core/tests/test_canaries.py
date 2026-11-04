"""Tests for prompt-leak canaries (maverick.safety.canaries)."""
from __future__ import annotations

from pathlib import Path

import pytest

# ---------- sandbox canaries ----------

def test_canaries_register_check(tmp_path):
    from maverick.safety.canaries import (
        SandboxCanaryFired,
        check,
        clear,
        is_canary,
        register,
    )
    clear()
    canary = tmp_path / "canary"
    register(canary)
    assert is_canary(canary)
    with pytest.raises(SandboxCanaryFired):
        check(canary, action="read")
    clear()


def test_canaries_no_op_when_unregistered(tmp_path):
    from maverick.safety.canaries import check, clear
    clear()
    # No canaries registered -> check() is a no-op.
    check(tmp_path / "file.txt")


def test_canaries_plant_and_verify(tmp_path):
    from maverick.safety.canaries import (
        clear,
        plant_session_canaries,
        verify_canaries,
    )
    clear()
    planted = plant_session_canaries(tmp_path)
    assert len(planted) == 3
    # All canary files exist with expected content.
    for p in planted:
        assert Path(p).exists()
    violations = verify_canaries(planted)
    assert violations == []
    # Tamper with one.
    Path(planted[0]).write_text("MUWAHAHAHA")
    violations = verify_canaries(planted)
    assert planted[0] in violations
    clear()


def test_canaries_unregister(tmp_path):
    from maverick.safety.canaries import clear, register, unregister
    clear()
    p = tmp_path / "c"
    register(p)
    assert unregister(p) is True
    assert unregister(p) is False

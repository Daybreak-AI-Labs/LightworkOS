"""The golden-path walkthrough drives the real governance/capability/audit/budget
code (no model) and emits tamper-evident receipts. See maverick/golden_path.py.
"""
from __future__ import annotations

import pytest
from maverick import golden_path


def test_golden_path_receipts(tmp_path):
    pytest.importorskip("cryptography")  # the demo's value is the signed receipts
    audit = tmp_path / "audit.ndjson"
    scenario = golden_path.run_scenario(audit, key_dir=tmp_path / "keys")

    # The storyline exercises every enforcement surface, in order.
    assert [s.verdict for s in scenario.steps] == [
        "SEALED", "DENY", "REQUIRE_HUMAN", "ALLOW", "CAPPED", "TAMPER-EVIDENT"]

    # The authentic chain verifies clean; the tamper produced a real break reason.
    assert scenario.chain_clean is True
    assert scenario.break_reason and "UNEXPECTED" not in scenario.break_reason

    # The on-disk signed file independently verifies under the run's key dir
    # (restore the global afterward so this test doesn't leak it either).
    from maverick.audit import signing
    saved = signing.KEY_DIR
    signing.KEY_DIR = tmp_path / "keys"
    try:
        assert audit.exists()
        assert not signing.verify_chain(audit)
    finally:
        signing.KEY_DIR = saved

    md = golden_path.render(scenario, audit)
    assert "Golden Path" in md
    assert "DENY" in md and "TAMPER-EVIDENT" in md

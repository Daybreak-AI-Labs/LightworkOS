"""Flow concurrency slots remain usable in the longest tenant namespace."""
from __future__ import annotations

import os
from pathlib import Path

from maverick.file_lock import _windows_extended_path
from maverick.flow.store import _safe_id
from maverick.paths import data_dir, reset_tenant, set_tenant
from maverick_dashboard.automation_queue import _flow_slot_guard


def test_slot_guard_accepts_deep_tenant_and_flow_id(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    tenant = "t" * 200
    flow_id = "f" * 120
    token = set_tenant(tenant)
    try:
        target = data_dir("flows", "slots", _safe_id(flow_id))
        assert os.name != "nt" or len(str(target)) > 260
        with _flow_slot_guard(flow_id):
            lock = target.parent / (target.name + ".lock")
            io_lock = Path(_windows_extended_path(lock) if os.name == "nt" else lock)
            assert io_lock.is_file()
    finally:
        reset_tenant(token)

"""/metrics exposes storage leading indicators (world-DB size + free disk) so an
SRE can alert before SQLite slows or the disk fills."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


def test_storage_gauges_present(tmp_path, monkeypatch):
    from maverick import world_model
    db = tmp_path / "world.db"
    world_model.WorldModel(db).create_goal("t", "d")
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    text = client.get("/metrics").text
    assert "# TYPE maverick_world_db_bytes gauge" in text
    assert "# TYPE maverick_data_disk_free_bytes gauge" in text
    # The DB file exists + has content, so the size gauge is > 0.
    line = next(ln for ln in text.splitlines()
                if ln.startswith("maverick_world_db_bytes "))
    assert int(line.split()[1]) > 0

"""Mixed settings review timing and startup-state projections."""
from types import SimpleNamespace

from maverick_dashboard import settings_runtime_status as status


def test_mixed_batch_activation_metadata():
    rows = [SimpleNamespace(id="dashboard.compress", restart=True),
            SimpleNamespace(id="dashboard.theme", restart=False),
            SimpleNamespace(id="budget.max_wall_seconds", restart=False)]
    assert [status.impact(row)["activation"] for row in rows] == ["restart", "immediate", "next_task"]


def test_runtime_projection_keeps_missing_receipt_unconfirmed(monkeypatch):
    value = SimpleNamespace(id="dashboard.compress", reader="maverick_dashboard.app", label="Compression", group="Performance",
                            path=("dashboard", "compress"), env=(), restart=True)
    monkeypatch.setattr(status.runtime_configuration, "enabled", lambda: True)
    monkeypatch.setattr(status.runtime_configuration, "records", lambda: ([], False))
    monkeypatch.setattr(status.config, "load_global_config", lambda: {"dashboard": {"compress": True}})
    monkeypatch.setattr(status.catalog, "BY_ID", {value.id: value})
    monkeypatch.setattr(status.page, "_sources", dict)
    monkeypatch.setattr(status.page, "_revision", lambda layers: "reviewed")
    result = status.projection([value.id])
    assert result["saved_revision"] == "reviewed"
    assert result["items"][0]["state"] == "unconfirmed"
    assert "sharing this configuration data folder" in result["coverage"]

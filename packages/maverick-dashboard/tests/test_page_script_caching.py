"""Page scripts that sent no cache policy of their own fell back to the
dashboard's ``no-store`` and were downloaded again on every view, while the
other bundled scripts are cached (immutable for their versioned URL)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app, static_version

_SCRIPTS = [
    "lightwork-task-views.js", "lightwork-approval-challenges.js",
    "lightwork-compliance-mapping-builder.js", "lightwork-installation-security.js",
    "lightwork-instruction-capture.js", "lightwork-source-analysis.js",
    "lightwork-local-flow-comparisons.js", "lightwork-local-flow-release.js",
    "lightwork-local-runtime.js", "lightwork-local-runtime.css",
    "lightwork-provider-spending.js", "lightwork-provider-spending.css",
    "lightwork-webhook-recovery.js",
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.mark.parametrize("name", _SCRIPTS)
def test_a_page_script_is_cached_like_its_siblings(client, name):
    plain = client.get(f"/static/{name}")
    assert plain.status_code == 200 and plain.content
    assert "no-store" not in plain.headers["cache-control"]
    assert "public" in plain.headers["cache-control"]
    version = static_version(name)
    assert version
    versioned = client.get(f"/static/{name}?v={version}")
    assert versioned.status_code == 200 and versioned.content == plain.content
    assert versioned.headers["cache-control"] == "public, max-age=31536000, immutable"

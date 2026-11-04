"""Every literal asset advertised by a shipped template must be served."""
from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient


def test_advertised_script_and_style_routes(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config
    from maverick_dashboard.app import app

    config.reset_config_cache()
    directory = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    names = set()
    for path in directory.glob("*.html"):
        source = re.sub(r"{#.*?#}", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
        names.update(re.findall(r"asset\(['\"]([a-zA-Z0-9_.-]+\.(?:js|css))['\"]\)", source))
        names.update(re.findall(r"/static/([a-zA-Z0-9_.-]+\.(?:js|css))", source))
    assert len(names) > 100  # Detect accidental narrowing to a few shell assets.
    failures = []
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    for name in sorted(names):
        response = client.get("/static/" + name)
        expected = "text/css" if name.endswith(".css") else "application/javascript"
        if response.status_code != 200 or response.headers.get("content-type", "").split(";", 1)[0] != expected:
            failures.append((name, response.status_code, response.headers.get("content-type")))
    assert not failures, "\n".join(map(str, failures))


def test_companion_navigation_reuses_current_page_authority(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import employee_companion_api as companion

    seen = []

    def allowed(request, *, admin):
        seen.append((request, admin))

    monkeypatch.setattr(companion, "_authority", allowed)
    request = object()
    assert companion.navigation_available(request)
    assert companion.navigation_available(request, admin=True)
    assert seen == [(request, False), (request, True)]

    def denied(request, *, admin):
        raise HTTPException(403, "Current membership is required")

    monkeypatch.setattr(companion, "_authority", denied)
    assert not companion.navigation_available(request)

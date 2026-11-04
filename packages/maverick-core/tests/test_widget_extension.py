"""Contract tests for the embeddable widget (extensions/widget).

Lives here — not under extensions/ — because the repo's pytest testpaths
(packages/apps/benchmarks) don't collect extensions/, same reason the
demo-cluster and multiarch contract tests live in this directory.

Static validation: the JS parses, talks only to the real dashboard endpoint
with the exact auth header the middleware accepts, pulls nothing from a CDN,
and the demo page wires it up same-origin.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WIDGET = _REPO_ROOT / "extensions" / "widget"
_JS = _WIDGET / "maverick-widget.js"
_DEMO = _WIDGET / "demo.html"


def test_widget_js_parses():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available to syntax-check the widget JS")
    proc = subprocess.run(
        [node, "--check", str(_JS)], capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


def test_widget_polls_the_real_goals_endpoint():
    js = _JS.read_text(encoding="utf-8")
    # /api/v1/goals is the real read endpoint (maverick_dashboard/api.py);
    # The widget does not use /api/v1/glance (the small-screen glance payload).
    assert '"/api/v1/goals?limit=100"' in js
    assert "glance" not in js.lower()


def test_widget_sends_exactly_the_bearer_header():
    js = _JS.read_text(encoding="utf-8")
    assert '"Authorization"' in js and '"Bearer " + token' in js
    # ?token= query auth was removed from the dashboard; never send it.
    assert "token=" not in re.sub(r"/\*.*?\*/", "", js, flags=re.DOTALL)


def test_widget_is_self_contained_no_cdn():
    # No absolute URLs at all: the only network target is the configured
    # endpoint + the relative API path.
    js = _JS.read_text(encoding="utf-8")
    assert "https://" not in js and "http://" not in js


def test_widget_is_read_only():
    js = _JS.read_text(encoding="utf-8")
    # Only GETs: fetch is never called with a method override or a body.
    assert "method:" not in js and "body:" not in js
    assert "POST" not in js and "DELETE" not in js and "PUT" not in js


def test_status_buckets_match_world_model_reality():
    js = _JS.read_text(encoding="utf-8")
    # blocked/cancelled are the real failure statuses (world_model.py);
    # 'failed' is only a defensive extra.
    for status in ('"pending"', '"active"', '"done"', '"blocked"', '"cancelled"'):
        assert status in js, status


def test_demo_page_embeds_widget_same_origin():
    html = _DEMO.read_text(encoding="utf-8")
    assert 'src="./maverick-widget.js"' in html
    assert 'data-endpoint=""' in html
    assert "https://" not in html  # no CDN, no hardcoded remote dashboards

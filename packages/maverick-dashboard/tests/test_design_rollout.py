"""Design-system rollout: a consistent .page-title across pages that drifted to
a bare <h2>, plus the shared .section-head component."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def test_pages_use_shared_page_title(monkeypatch, tmp_path):
    # agents/roles/skills used a bare lowercase <h2>; now the shared <h1>.
    _isolate(monkeypatch, tmp_path)
    c = _client()
    import re
    for path, label in [("/agents", "Agent Factory"), ("/roles", "Roles"), ("/skills", "Skills"),
                        ("/plugins", "Plugins"), ("/safety", "Safety"), ("/compliance", "Compliance")]:
        t = c.get(path).text
        # The shared <h1 class="page-title"> — plain, or via the hero
        # component which adds hero-title and an id.
        assert re.search(
            r'<h1 class="page-title[^"]*"[^>]*>' + re.escape(label), t), path


def test_generic_empties_use_mv_empty():
    # Generic full-page empties converged onto the single .mv-empty component.
    # Asserted against the template source: whether a live render shows the
    # empty branch depends on seeded data, and the stylesheet no longer ships
    # inline to mask that (the old page-text assertion matched the CSS rule).
    import pathlib
    base = pathlib.Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    for f in ["benchmarks.html", "compartments.html", "store.html"]:
        assert "mv-empty" in (base / f).read_text(encoding="utf-8"), f


def test_store_modernized_off_bespoke_classes(monkeypatch, tmp_path):
    # store was a token opt-out (.store-card/.store-grid, raw 8px); now rebuilt
    # on the shared .card/.card-grid + .btn.
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/store").text
    assert "store-card" not in t and "store-grid" not in t
    assert "border-radius: 8px" not in t


def test_buttons_have_tactile_transition(monkeypatch, tmp_path):
    # Buttons gained a smooth transition + a subtle press, gated by reduced motion.
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/static/lightwork.css").text
    assert ".btn:active { transform: translateY(1px); }" in t
    assert ".btn:active { transform: none; }" in t


def test_automations_uses_shared_section_head(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/automations").text
    assert 'class="section-head"' in t and "auto__section-head" not in t


def test_section_titles_have_one_size():
    # A bare <h2> (a panel's title) rendered at 12px while the same title in
    # a .section-head rendered at 18px. Section titles share one size now.
    import pathlib
    import re
    css = (pathlib.Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork.css").read_text(encoding="utf-8")
    base = re.search(r"(?m)^\s*h2 \{([^}]*)\}", css)
    assert base is not None
    assert "font-size: var(--text-lg)" in base.group(1)
    section_head = re.search(r"\.section-head h2 \{([^}]*)\}", css)
    assert section_head is not None and "font-size: var(--text-lg)" in section_head.group(1)

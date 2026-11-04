"""The neon-lab design system's assets are served same-origin and public:
the brand mark and the self-hosted faces load on the login and share pages
before any session exists, and the font route is an allowlist, never a
directory listing."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app


@pytest.fixture
def noauth(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "secret-token")  # pragma: allowlist secret
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_brand_mark_is_public_png(noauth):
    r = noauth.get("/static/daybreak-mark.png")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/png")
    assert len(r.content) > 1000


@pytest.mark.parametrize("name", ["manrope-var.woff2", "jbm-400.woff2", "jbm-500.woff2"])
def test_fonts_are_public_immutable_woff2(noauth, name):
    r = noauth.get(f"/static/fonts/{name}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("font/woff2")
    assert "immutable" in r.headers["cache-control"]
    assert r.content[:4] == b"wOF2"


# A literal "../" is normalized by the client before it is sent, so it would
# request /static/lightwork.css itself (public: the sign-in page needs it); the
# encoded traversal is what actually reaches the font route.
@pytest.mark.parametrize("name", ["..%2Flightwork.css", "inter-400.woff2", "manrope-200.ttf", "..%2F..%2Fapp.py",
                                  # The six byte-identical per-weight copies are gone with the single file.
                                  "manrope-200.woff2", "manrope-700.woff2",
                                  # The fonts' licence ships beside them but is not a face.
                                  "OFL.txt"])
def test_font_route_is_an_allowlist(noauth, name):
    assert noauth.get(f"/static/fonts/{name}").status_code in (401, 404)   # not on the allowlist: gated or missing, never served


def test_stylesheet_declares_the_faces_and_the_dark_stage_tokens(noauth):
    css = noauth.get("/static/lightwork.css", headers={"Authorization": "Bearer secret-token"}).text
    assert 'font-family: "Manrope"' in css and 'font-family: "JetBrains Mono"' in css
    assert "url(/static/fonts/manrope-var.woff2)" in css
    assert "--bg: #04050A" in css and "--grad: linear-gradient" in css
    assert "color-scheme: dark;" in css and "color-scheme: light;" in css   # the theme pair survives the layer


_STATIC = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"
_PRELOAD = '<link rel="preload" href="/static/fonts/manrope-var.woff2" as="font" type="font/woff2" crossorigin>'


def test_manrope_is_one_variable_face_downloaded_once():
    """Manrope is a variable font: one file covers every weight the pages use,
    so the sheet declares one face over the weight range instead of six faces
    that each made the browser download the same 24 KB file again."""
    css = (_STATIC / "lightwork.css").read_text(encoding="utf-8")
    faces = re.findall(r"@font-face\s*\{([^}]*)\}", css)
    manrope = [face for face in faces if '"Manrope"' in face]
    assert len(manrope) == 1, manrope
    assert re.search(r"font-weight:\s*200 700;", manrope[0])
    assert "url(/static/fonts/manrope-var.woff2)" in manrope[0]
    assert "font-display: swap" in manrope[0]


def test_public_font_paths_are_exactly_the_declared_files():
    """Signed-out pages load these fonts before any session exists, so the
    auth-exempt set, the font route's allowlist and the shipped files all
    match the faces the stylesheet declares -- no more, no fewer."""
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import auth

    css = (_STATIC / "lightwork.css").read_text(encoding="utf-8")
    declared = set(re.findall(r"url\((/static/fonts/[^)]+)\)", css))
    assert declared == {"/static/fonts/manrope-var.woff2", "/static/fonts/jbm-400.woff2", "/static/fonts/jbm-500.woff2"}
    assert {path for path in auth.PUBLIC_STATIC_PATHS if path.startswith("/static/fonts/")} == declared
    assert {"/static/fonts/" + name for name in dash_app._FONT_FILES} == declared
    shipped = {"/static/fonts/" + path.name for path in (_STATIC / "fonts").iterdir() if path.suffix == ".woff2"}
    assert shipped == declared
    # The SIL Open Font License the faces require ships with them; no other file does.
    assert {path.name for path in (_STATIC / "fonts").iterdir() if path.suffix != ".woff2"} == {"OFL.txt"}


@pytest.mark.parametrize("shell", ["base.html", "chat_base.html", "public_base.html"])
def test_shells_preload_the_font_the_first_paint_needs(shell):
    # Fonts are fetched in CORS mode, so the preload needs crossorigin to be reused.
    source = (_STATIC.parent / "templates" / shell).read_text(encoding="utf-8")
    assert source.count(_PRELOAD) == 1


@pytest.mark.parametrize("path", ["/start", "/chat"])
def test_rendered_pages_preload_the_font_once(noauth, path, monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    page = noauth.get(path, headers={"Authorization": "Bearer secret-token"}).text
    assert page.count(_PRELOAD) == 1
    assert "manrope-200.woff2" not in page


def test_shell_uses_the_mark(noauth):
    page = noauth.get("/start", headers={"Authorization": "Bearer secret-token"}).text
    assert "/static/daybreak-mark.png" in page
    assert "/static/daybreak-logo.jpg" in page   # favicon stays on the lockup


def test_brand_mark_is_sized_for_the_top_bar():
    # Shown 30 px tall in both shells; the 425 x 323 original (154 KB) was
    # the largest download on every page, before any of the page's text,
    # on a slow phone connection. Three times the shown size stays sharp.
    import struct
    from pathlib import Path

    data = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "daybreak-mark.png").read_bytes()
    width, height = struct.unpack(">II", data[16:24])
    assert height >= 90 and len(data) < 25_000

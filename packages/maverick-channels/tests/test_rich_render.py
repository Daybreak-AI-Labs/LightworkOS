"""KaTeX/Mermaid rich-render layer: detection, artifact, channel wrapper."""
from __future__ import annotations

import asyncio
import time

from maverick_channels import rich_render as rr

_MATHY = "energy is $$E = mc^2$$ and inline \\(a+b\\)"
_DIAGRAM = "flow:\n```mermaid\ngraph TD; A-->B;\n```\ndone"


def test_detect_counts():
    c = rr.detect_rich_blocks(_MATHY)
    assert c["math"] == 2 and c["mermaid"] == 0
    c = rr.detect_rich_blocks(_DIAGRAM)
    assert c["mermaid"] == 1
    assert rr.detect_rich_blocks("plain") == {"math": 0, "mermaid": 0}
    assert rr.has_rich_blocks(_MATHY) and not rr.has_rich_blocks("plain")


def test_detect_unmatched_inline_math_is_linear():
    payload = r"\(" * 20_000
    start = time.perf_counter()
    assert rr.detect_rich_blocks(payload) == {"math": 0, "mermaid": 0}
    assert time.perf_counter() - start < 0.5


def test_render_html_escapes_and_embeds():
    html = rr.render_html("<script>alert(1)</script> $$x^2$$")
    assert "<script>alert(1)</script>" not in html  # content escaped
    assert "&lt;script&gt;" in html
    assert "$$x^2$$" in html          # math left for KaTeX auto-render
    assert "katex" in html


def test_render_html_mermaid_block():
    html = rr.render_html(_DIAGRAM)
    assert '<pre class="mermaid">' in html
    assert "graph TD; A--&gt;B;" in html  # source escaped inside the block
    assert "mermaid" in html.lower()


def test_write_artifact_0600(tmp_path):
    from maverick.file_lock import private_path_is_restricted

    p = rr.write_artifact(_MATHY, out_dir=tmp_path)
    assert p.exists() and p.suffix == ".html"
    assert private_path_is_restricted(p)
    # same text -> same artifact path (content-addressed)
    assert rr.write_artifact(_MATHY, out_dir=tmp_path) == p


class _Chan:
    name = "fake"

    def __init__(self):
        self.sent: list[tuple[str, str]] = []

    async def send(self, user_id, text):
        self.sent.append((user_id, text))


def test_plain_text_passes_through(tmp_path):
    inner = _Chan()
    ch = rr.RichRenderChannel(inner, out_dir=tmp_path)
    asyncio.run(ch.send("u1", "no rich content"))
    assert inner.sent == [("u1", "no rich content")]


def test_rich_text_without_file_transport_never_sends_a_server_path(tmp_path):
    # Without a file hand-off the reply is kept intact and the limitation is
    # explained; a server-local artifact path is never sent as if it were a link.
    inner = _Chan()
    ch = rr.RichRenderChannel(inner, out_dir=tmp_path)
    asyncio.run(ch.send("u1", _MATHY))
    (uid, text), = inner.sent
    assert uid == "u1"
    assert text.startswith(_MATHY)
    assert "This chat cannot attach a rendered copy." in text
    assert ".html" not in text and str(tmp_path) not in text
    assert list(tmp_path.iterdir()) == []


def test_rich_text_with_deliver_hook(tmp_path):
    inner = _Chan()
    delivered: list = []

    async def deliver(user_id, path):
        delivered.append((user_id, path))

    ch = rr.RichRenderChannel(inner, deliver=deliver, out_dir=tmp_path)
    asyncio.run(ch.send("u1", _DIAGRAM))
    assert delivered and delivered[0][0] == "u1"
    assert delivered[0][1].exists()
    # the text notes the render but does NOT carry the path (file was shipped)
    assert ".html" not in inner.sent[0][1]


def test_render_failure_falls_back_to_plain(tmp_path, monkeypatch):
    inner = _Chan()
    delivered: list = []

    async def deliver(user_id, path):
        delivered.append((user_id, path))

    monkeypatch.setattr(rr, "write_artifact",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    ch = rr.RichRenderChannel(inner, deliver=deliver, out_dir=tmp_path)
    asyncio.run(ch.send("u1", _MATHY))
    assert inner.sent == [("u1", _MATHY)]  # reply never lost
    assert delivered == []


def test_wrapper_proxies_inner_attributes(tmp_path):
    inner = _Chan()
    ch = rr.RichRenderChannel(inner, out_dir=tmp_path)
    assert ch.name == "fake"


def test_maybe_wrap_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_CHANNELS_RICH_RENDER", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    inner = _Chan()
    assert rr.maybe_wrap(inner) is inner


def test_maybe_wrap_env_enables(monkeypatch):
    monkeypatch.setenv("MAVERICK_CHANNELS_RICH_RENDER", "1")
    inner = _Chan()
    assert isinstance(rr.maybe_wrap(inner), rr.RichRenderChannel)

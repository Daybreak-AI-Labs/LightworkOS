"""Docs MT pipeline: segmentation, quality gate, staleness, run loop."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import docs_i18n

_DOC = """# Title

Install Lightwork with pip install and set ANTHROPIC_API_KEY.

```bash
maverick init
```

More prose about config.toml here.
"""


def test_split_segments_roundtrip_and_fences():
    segments = docs_i18n.split_segments(_DOC)
    assert "".join(chunk for _, chunk in segments) == _DOC
    keeps = [chunk for mode, chunk in segments if mode == "keep"]
    assert len(keeps) == 1 and "maverick init" in keeps[0]


def test_verify_translation_gates():
    ok = _DOC.replace("Install", "Instalar").replace("More prose", "Más prosa")
    assert docs_i18n.verify_translation(_DOC, ok) == []
    assert "empty translation" in docs_i18n.verify_translation(_DOC, "  ")
    no_fence = ok.replace("```bash", "").replace("```", "")
    assert any("fence" in p for p in docs_i18n.verify_translation(_DOC, no_fence))
    lost = ok.replace("ANTHROPIC_API_KEY", "CLAVE_API")
    assert any("ANTHROPIC_API_KEY" in p
               for p in docs_i18n.verify_translation(_DOC, lost))
    fewer_heads = ok.replace("# Title", "Title")
    assert any("heading" in p
               for p in docs_i18n.verify_translation(_DOC, fewer_heads))


class _FakeResp:
    def __init__(self, text):
        self.text = text


class _FakeLLM:
    """Echoes prose with a marker so glossary/structure survive."""

    def __init__(self, mangle=False):
        self.mangle = mangle
        self.calls = 0

    def complete(self, system, messages, max_tokens, model):
        self.calls += 1
        text = messages[0]["content"]
        if self.mangle:
            return _FakeResp(text.replace("ANTHROPIC_API_KEY", "KEY"))
        return _FakeResp(text.replace("Install", "[xx] Install"))


def test_translate_document_preserves_code_and_gates():
    out = docs_i18n.translate_document(_DOC, "Spanish", _FakeLLM())
    assert "maverick init" in out and "[xx] Install" in out
    with pytest.raises(ValueError, match="quality gate"):
        docs_i18n.translate_document(_DOC, "Spanish", _FakeLLM(mangle=True))


def _setup_root(tmp_path: Path) -> Path:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "getting-started.md").write_text(_DOC, encoding="utf-8")
    return root


def test_status_and_run(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    root = _setup_root(tmp_path)
    files = ["getting-started.md"]

    (st,) = docs_i18n.status(root, ["ar"], files)
    assert st.state == "missing"

    written = docs_i18n.run(root, ["ar"], files, _FakeLLM())
    assert written and written[0].read_text(encoding="utf-8").startswith("<!-- source:")
    (st,) = docs_i18n.status(root, ["ar"], files)
    assert st.state == "current"
    assert docs_i18n.run(root, ["ar"], files, _FakeLLM()) == []  # skip current

    # source moved -> stale -> retranslated
    (root / "getting-started.md").write_text(_DOC + "\nNew line.\n", encoding="utf-8")
    (st,) = docs_i18n.status(root, ["ar"], files)
    assert st.state == "stale"
    assert docs_i18n.run(root, ["ar"], files, _FakeLLM())


def test_human_translation_never_overwritten(tmp_path):
    root = _setup_root(tmp_path)
    human = root / "i18n" / "fr" / "getting-started.md"
    human.parent.mkdir(parents=True)
    human.write_text("<!-- traduction communautaire -->\nBonjour.\n", encoding="utf-8")
    (st,) = docs_i18n.status(root, ["fr"], ["getting-started.md"])
    assert st.state == "unverified"
    llm = _FakeLLM()
    assert docs_i18n.run(root, ["fr"], ["getting-started.md"], llm) == []
    assert llm.calls == 0 and "Bonjour" in human.read_text(encoding="utf-8")


def test_check_mode_offline(tmp_path, capsys):
    root = _setup_root(tmp_path)
    rc = docs_i18n.main(["--docs-root", str(root), "--langs", "ar,tr", "--check"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ar\tgetting-started.md\tmissing" in out and "tr\t" in out


def test_rejects_source_paths_outside_docs_root(tmp_path):
    root = _setup_root(tmp_path)
    outside = tmp_path / "secret.md"
    outside.write_text("# Secret\n", encoding="utf-8")

    for rel in (str(outside), "../secret.md"):
        with pytest.raises(ValueError, match="docs file"):
            docs_i18n.status(root, ["ar"], [rel])
        with pytest.raises(ValueError, match="docs file"):
            docs_i18n.run(root, ["ar"], [rel], _FakeLLM())


def test_rejects_language_paths_outside_i18n_root(tmp_path):
    root = _setup_root(tmp_path)
    outside_dir = tmp_path / "outside"

    for lang in (str(outside_dir), "../outside"):
        with pytest.raises(ValueError, match="language code"):
            docs_i18n.status(root, [lang], ["getting-started.md"])
        with pytest.raises(ValueError, match="language code"):
            docs_i18n.run(root, [lang], ["getting-started.md"], _FakeLLM())

    assert not outside_dir.exists()

"""Optional OCR fallback for the computer-use screenshot action.

Off by default; appends an <ocr> block when MAVERICK_COMPUTER_OCR is set
and OCR yields text. Fail-open when OCR deps are absent. Tests mock the
screenshot + OCR so they need neither mss/pillow/tesseract nor a display.
"""
from __future__ import annotations

import base64
from pathlib import Path

import maverick.tools as tools
from maverick.tools import computer


def test_ocr_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_COMPUTER_OCR", raising=False)
    monkeypatch.setattr(computer, "_screenshot_png_b64", lambda: "FAKEB64")
    out = computer._run_computer_action({"action": "screenshot"})
    assert "<screenshot" in out
    assert "<ocr>" not in out


def test_ocr_appended_when_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_OCR", "1")
    monkeypatch.setattr(computer, "_screenshot_png_b64", lambda: "FAKEB64")
    monkeypatch.setattr(computer, "_ocr_png_b64", lambda b64: "Login\nSubmit")
    out = computer._run_computer_action({"action": "screenshot"})
    assert "<screenshot" in out
    assert "<ocr>Login\nSubmit</ocr>" in out


def test_ocr_enabled_but_no_text_omits_block(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_OCR", "on")
    monkeypatch.setattr(computer, "_screenshot_png_b64", lambda: "FAKEB64")
    monkeypatch.setattr(computer, "_ocr_png_b64", lambda b64: "")
    out = computer._run_computer_action({"action": "screenshot"})
    assert "<ocr>" not in out


def test_ocr_helper_uses_sandbox_run_with_timeout(monkeypatch):
    captured = {}

    def fake_sandbox_run(sandbox, argv, *, timeout=120.0, stdin=None):
        captured["sandbox"] = sandbox
        captured["argv"] = argv
        captured["timeout"] = timeout
        captured["stdin"] = stdin
        captured["tmp_path"] = argv[1]
        assert Path(argv[1]).read_bytes() == b"png-bytes"
        return 0, " Login\nSubmit \n", ""

    monkeypatch.setattr(tools, "sandbox_run", fake_sandbox_run)

    out = computer._ocr_png_b64(base64.b64encode(b"png-bytes").decode("ascii"))

    assert out == "Login\nSubmit"
    assert captured["sandbox"] is None
    assert captured["argv"][:2] == ["tesseract", captured["tmp_path"]]
    assert captured["argv"][2:] == ["-", "-l", "eng", "--psm", "3"]
    assert captured["timeout"] == 120
    assert captured["stdin"] is None
    assert not Path(captured["tmp_path"]).exists()


def test_ocr_helper_fail_open_on_tesseract_error(monkeypatch):
    def fake_sandbox_run(sandbox, argv, *, timeout=120.0, stdin=None):
        return 124, "", "TIMEOUT after 120s"

    monkeypatch.setattr(tools, "sandbox_run", fake_sandbox_run)

    assert computer._ocr_png_b64(base64.b64encode(b"png-bytes").decode("ascii")) == ""


def test_ocr_helper_fail_open_on_bad_base64():
    assert computer._ocr_png_b64("not-even-valid-b64") == ""

"""Tests for the Dropbox tool (maverick.tools.dropbox_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for n, v in methods.items():
        setattr(mod, n, v)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body, *, text=None):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = text if text is not None else str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = text if text is not None else str(body)
    r.content = (body if isinstance(body, bytes) else str(body).encode())
    return r


# ---------- Dropbox ----------

def test_dropbox_requires_op():
    from maverick.tools.dropbox_tool import dropbox_tool
    assert "op is required" in dropbox_tool().fn({})


def test_dropbox_missing_token(monkeypatch):
    monkeypatch.delenv("DROPBOX_ACCESS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.dropbox_tool import dropbox_tool
    out = dropbox_tool().fn({"op": "list", "path": "/"})
    assert "DROPBOX_ACCESS_TOKEN" in out


def test_dropbox_upload_dry_run(monkeypatch):
    monkeypatch.setenv("DROPBOX_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.dropbox_tool import dropbox_tool
    out = dropbox_tool().fn({"op": "upload", "path": "/x.txt", "content": "hi"})
    assert "DRY RUN" in out


def test_dropbox_share_dry_run(monkeypatch):
    monkeypatch.setenv("DROPBOX_ACCESS_TOKEN", "tok")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.dropbox_tool import dropbox_tool
    out = dropbox_tool().fn({"op": "share", "path": "/x.txt"})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_dropbox_list_renders(monkeypatch):
    monkeypatch.setenv("DROPBOX_ACCESS_TOKEN", "tok")
    body = {"entries": [
        {".tag": "file", "name": "a.txt", "size": 10, "path_display": "/a.txt"},
    ]}
    _fake_httpx(monkeypatch, post=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.dropbox_tool import dropbox_tool
    out = dropbox_tool().fn({"op": "list", "path": ""})
    assert "/a.txt" in out


def test_dropbox_download_requests_only_the_preview_range(monkeypatch):
    monkeypatch.setenv("DROPBOX_ACCESS_TOKEN", "tok")
    resp = _resp(206, b"x" * 4097)
    resp.headers = {"Dropbox-API-Result": '{"size": 99999}'}
    post = MagicMock(return_value=resp)
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.dropbox_tool import dropbox_tool
    out = dropbox_tool().fn({"op": "download", "path": "/big.bin"})
    assert post.call_args.kwargs["headers"]["Range"] == "bytes=0-4096"
    assert out.startswith("size=99999") and out.endswith("(truncated)")
